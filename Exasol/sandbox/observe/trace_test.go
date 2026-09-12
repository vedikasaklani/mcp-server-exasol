package observe

import (
	"strings"
	"testing"
	"time"
)

// These fixture lines are copied verbatim from a real runsc
// release-20260406.0 --debug-log-format=json capture (see the sandbox
// integration testing session) — not hand-constructed guesses at the
// format.
const (
	fixtureEnterSimple  = `{"msg":"strace.go:564] [   1:   1] probe E arch_prctl(0x1002, 0x68b908)","level":"debug","time":"2026-09-10T21:57:42.921879000+05:30"}`
	fixtureExitSimple   = `{"msg":"strace.go:602] [   1:   1] probe X arch_prctl(0x1002, 0x68b908) = 0 (0x0) (2.208µs)","level":"debug","time":"2026-09-10T21:57:42.921882208+05:30"}`
	fixtureExitWithPath = `{"msg":"strace.go:608] [   1:   1] probe X openat(AT_FDCWD /home/neal/Programming/Exasol, 0x679ab0 /sys/kernel/mm/transparent_hugepage/hpage_pmd_size, O_RDONLY|0x0, 0o0) = 0 (0x0) errno=2 (no such file or directory) (5.1µs)","level":"debug","time":"2026-09-10T21:57:42.921888000+05:30"}`
	fixtureNonStrace    = `{"msg":"config.go:484] Debug: true. Strace: true, max size: 1024, syscalls: ","level":"info","time":"2026-09-10T21:57:42.892645161+05:30"}`
	fixtureNotJSON      = `not even json`
)

func TestParseLine_EnterEvent(t *testing.T) {
	ev, ok := ParseLine(fixtureEnterSimple)
	if !ok {
		t.Fatalf("expected a parsed event")
	}
	if ev.Direction != DirEnter {
		t.Errorf("Direction = %v, want enter", ev.Direction)
	}
	if ev.Syscall != "arch_prctl" {
		t.Errorf("Syscall = %q, want arch_prctl", ev.Syscall)
	}
	if ev.Process != "probe" {
		t.Errorf("Process = %q, want probe", ev.Process)
	}
	if ev.ThreadGrp != 1 || ev.ThreadID != 1 {
		t.Errorf("ThreadGrp/ThreadID = %d/%d, want 1/1", ev.ThreadGrp, ev.ThreadID)
	}
}

func TestParseLine_ExitEventWithDuration(t *testing.T) {
	ev, ok := ParseLine(fixtureExitSimple)
	if !ok {
		t.Fatalf("expected a parsed event")
	}
	if ev.Direction != DirExit {
		t.Errorf("Direction = %v, want exit", ev.Direction)
	}
	if ev.ReturnValue != 0 {
		t.Errorf("ReturnValue = %d, want 0", ev.ReturnValue)
	}
	if ev.HasErrno {
		t.Errorf("HasErrno = true, want false (this call succeeded)")
	}
	want := 2208 * time.Nanosecond
	if ev.Duration != want {
		t.Errorf("Duration = %v, want %v", ev.Duration, want)
	}
}

func TestParseLine_ExitEventWithErrnoAndPath(t *testing.T) {
	ev, ok := ParseLine(fixtureExitWithPath)
	if !ok {
		t.Fatalf("expected a parsed event")
	}
	if ev.Syscall != "openat" {
		t.Errorf("Syscall = %q, want openat", ev.Syscall)
	}
	if !ev.HasErrno || ev.Errno != 2 || ev.ErrnoName != "no such file or directory" {
		t.Errorf("errno = (%v, %d, %q), want (true, 2, \"no such file or directory\")", ev.HasErrno, ev.Errno, ev.ErrnoName)
	}
	paths := ev.Paths()
	if len(paths) != 1 || paths[0] != "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size" {
		t.Errorf("Paths() = %v, want exactly the pointer-decoded path, not the AT_FDCWD context path", paths)
	}
}

func TestParseLine_SkipsNonStraceLines(t *testing.T) {
	if _, ok := ParseLine(fixtureNonStrace); ok {
		t.Errorf("expected non-strace log lines to be skipped, not parsed")
	}
	if _, ok := ParseLine(fixtureNotJSON); ok {
		t.Errorf("expected malformed JSON to be skipped, not to error out the whole parse")
	}
}

func TestParseStream_SkipsUnparseableAndKeepsOrder(t *testing.T) {
	input := strings.Join([]string{
		fixtureNonStrace,
		fixtureEnterSimple,
		fixtureNotJSON,
		fixtureExitSimple,
		fixtureExitWithPath,
	}, "\n")

	events, err := ParseStream(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 parsed events, got %d", len(events))
	}
	if events[0].Syscall != "arch_prctl" || events[0].Direction != DirEnter {
		t.Errorf("events[0] = %+v, want arch_prctl enter", events[0])
	}
	if events[2].Syscall != "openat" {
		t.Errorf("events[2] = %+v, want openat", events[2])
	}
}
