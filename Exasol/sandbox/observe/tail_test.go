package observe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// logLineJSON builds a runsc --debug-log-format=json line carrying an
// strace message, matching the shape ParseLine was reverse engineered
// against.
func logLineJSON(t *testing.T, at time.Time, body string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"msg":  "strace.go:600] " + body,
		"time": at.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b) + "\n"
}

func drainFor(ch <-chan SyscallEvent, d time.Duration) []SyscallEvent {
	var out []SyscallEvent
	deadline := time.After(d)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline:
			return out
		}
	}
}

func TestTailer_FollowsAFileThatIsStillBeingWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runsc.log.boot")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tailer := &Tailer{Dir: dir, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := tailer.Follow(ctx)

	now := time.Now()
	for i := 0; i < 5; i++ {
		fmt.Fprint(f, logLineJSON(t, now, fmt.Sprintf("[   1:   1] node X openat(AT_FDCWD /w, 0x1 /f%d, O_RDONLY|0x0, 0o0) = 3 (0x3) (5µs)", i)))
		time.Sleep(15 * time.Millisecond)
	}

	got := drainFor(events, 500*time.Millisecond)
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5 — the tailer must pick up appends without the writer closing the file", len(got))
	}
	if got[0].Syscall != "openat" {
		t.Errorf("syscall = %q", got[0].Syscall)
	}
}

func TestTailer_DiscoversFilesCreatedAfterItStarted(t *testing.T) {
	dir := t.TempDir()
	tailer := &Tailer{Dir: dir, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := tailer.Follow(ctx)

	time.Sleep(30 * time.Millisecond) // start with an empty directory
	path := filepath.Join(dir, "late.log")
	if err := os.WriteFile(path, []byte(logLineJSON(t, time.Now(),
		"[   1:   1] node X write(0x1, 0x2 \"hi\", 0x2) = 2 (0x2) (3µs)")), 0o644); err != nil {
		t.Fatal(err)
	}

	got := drainFor(events, 500*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 — runsc creates its log files after the process starts", len(got))
	}
}

func TestTailer_HandlesPartiallyWrittenLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	tailer := &Tailer{Dir: dir, PollInterval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := tailer.Follow(ctx)

	full := logLineJSON(t, time.Now(), "[   1:   1] node X read(0x3, 0x2, 0x400) = 128 (0x80) (9µs)")
	half := len(full) / 2
	fmt.Fprint(f, full[:half])
	time.Sleep(40 * time.Millisecond)
	if got := drainFor(events, 50*time.Millisecond); len(got) != 0 {
		t.Fatalf("half a JSON object must not parse as an event, got %d", len(got))
	}
	fmt.Fprint(f, full[half:])

	got := drainFor(events, 500*time.Millisecond)
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1 once the line was completed", len(got))
	}
	if got[0].ReturnValue != 128 {
		t.Errorf("return value = %d, want 128", got[0].ReturnValue)
	}
}

func TestTailer_DropsRatherThanGrowingWhenConsumerStalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flood.log")
	var payload []byte
	now := time.Now()
	for i := 0; i < 200; i++ {
		payload = append(payload, logLineJSON(t, now, "[   1:   1] node X getpid() = 1 (0x1) (1µs)")...)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	// A buffer far smaller than the backlog, and nothing reading it.
	tailer := &Tailer{Dir: dir, PollInterval: 10 * time.Millisecond, Buffer: 8}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = tailer.Follow(ctx)
	time.Sleep(150 * time.Millisecond)

	st := tailer.Stats()
	if st.Dropped == 0 {
		t.Fatalf("a stalled consumer must produce counted drops, not unbounded buffering: %+v", st)
	}
	if st.EventsParsed < 8 {
		t.Fatalf("expected the buffer to fill first; parsed %d", st.EventsParsed)
	}
}

func TestTailer_TruncatesConsumedLogPastLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	line := logLineJSON(t, time.Now(), "[   1:   1] node X getpid() = 1 (0x1) (1µs)")
	var payload []byte
	for i := 0; i < 100; i++ {
		payload = append(payload, line...)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	tailer := &Tailer{Dir: dir, PollInterval: 10 * time.Millisecond, MaxBytesPerFile: int64(len(line) * 10)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := tailer.Follow(ctx)
	drainFor(events, 300*time.Millisecond)

	if tailer.Stats().Truncations == 0 {
		t.Fatalf("a log past its size limit must be truncated; a container running for days would otherwise fill the disk")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() >= int64(len(payload)) {
		t.Fatalf("file is still %d bytes; truncation did not take effect", fi.Size())
	}
}

func TestTailer_FinalPassOnCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last.log")
	tailer := &Tailer{Dir: dir, PollInterval: time.Hour} // never ticks
	ctx, cancel := context.WithCancel(context.Background())
	events := tailer.Follow(ctx)

	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte(logLineJSON(t, time.Now(),
		"[   1:   1] node X execve(0x1 /bin/sh, 0x2, 0x3) = 0 (0x0) (40µs)")), 0o644); err != nil {
		t.Fatal(err)
	}
	cancel()

	got := drainFor(events, time.Second)
	if len(got) != 1 {
		t.Fatalf("got %d events; the last thing a container does before teardown must not be lost", len(got))
	}
	if got[0].Syscall != "execve" {
		t.Errorf("syscall = %q", got[0].Syscall)
	}
}
