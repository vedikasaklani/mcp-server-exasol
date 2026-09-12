package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newLog(t *testing.T, path string) *Log {
	t.Helper()
	l, err := Open(Config{
		Path: path, SessionID: "sess_test", ServerID: "srv_test",
		ImageDigest: "sha256:abc", CheckpointEvery: 5,
		CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

func TestLog_ChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newLog(t, path)
	for i := 0; i < 12; i++ {
		l.Append(Entry{
			Kind: KindExecution, RequestID: "req",
			Execution: &Execution{ToolName: "read_file", Status: "SUCCESS", LatencyMS: int64(i)},
			Sandbox:   &Sandbox{Runtime: "runsc", SeccompDenials: 0, AttributionExact: true},
		})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rep, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("chain did not verify: %v", rep.Problems)
	}
	if rep.Executions != 12 {
		t.Errorf("executions = %d, want 12", rep.Executions)
	}
	if rep.Checkpoints == 0 {
		t.Errorf("no checkpoints written; §7.1 requires a signed checkpoint every N entries")
	}
}

func TestLog_DetectsAModifiedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newLog(t, path)
	for i := 0; i < 6; i++ {
		l.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "t", Status: "SUCCESS"}})
	}
	l.Close()

	// Rewrite one entry's content, leaving its hash alone — the shape of
	// someone editing the log to hide what a tool call did.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var e Entry
	if err := json.Unmarshal([]byte(lines[2]), &e); err != nil {
		t.Fatal(err)
	}
	e.Execution.Status = "DENIED"
	edited, _ := json.Marshal(e)
	lines[2] = string(edited)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Valid {
		t.Fatalf("a modified entry must not verify")
	}
	joined := strings.Join(rep.Problems, "\n")
	if !strings.Contains(joined, "does not match its hash") {
		t.Errorf("the report must name the modified entry: %v", rep.Problems)
	}
}

func TestLog_DetectsADeletedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newLog(t, path)
	for i := 0; i < 6; i++ {
		l.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "t", Status: "SUCCESS"}})
	}
	l.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Removing an entry is the cheapest way to hide a call; the chain
	// link is what makes it visible.
	lines = append(lines[:2], lines[3:]...)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	rep, _ := Verify(path)
	if rep.Valid {
		t.Fatalf("a deleted entry must break the chain")
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "chain break") {
		t.Errorf("expected a chain break, got %v", rep.Problems)
	}
}

func TestLog_DetectsAForgedCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := newLog(t, path)
	for i := 0; i < 6; i++ {
		l.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "t", Status: "SUCCESS"}})
	}
	l.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	tampered := false
	for i, line := range lines {
		var e Entry
		if json.Unmarshal([]byte(line), &e) != nil || e.Kind != KindCheckpoint {
			continue
		}
		// Re-point the checkpoint at a different head and re-hash the
		// entry so only the signature is wrong.
		e.Checkpoint.ChainHead = GenesisHash
		h, _ := e.Digest()
		e.Hash = h
		b, _ := json.Marshal(e)
		lines[i] = string(b)
		tampered = true
		break
	}
	if !tampered {
		t.Skip("no checkpoint written to tamper with")
	}
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	rep, _ := Verify(path)
	if rep.Valid {
		t.Fatalf("a checkpoint whose signature does not cover its claimed head must not verify")
	}
}

func TestLog_ResumesAnExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1 := newLog(t, path)
	l1.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "a", Status: "SUCCESS"}})
	l1.Close()
	head1 := l1.Stats().ChainHead

	l2 := newLog(t, path)
	l2.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "b", Status: "SUCCESS"}})
	l2.Close()

	rep, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("a resumed chain must still verify end to end: %v", rep.Problems)
	}
	if rep.Executions != 2 {
		t.Errorf("executions = %d, want 2 — restarting must extend the chain, not fork it", rep.Executions)
	}
	if head1 == "" || head1 == GenesisHash {
		t.Errorf("first session left no chain head to resume from")
	}
}

func TestLog_RecordsItsOwnGapsRatherThanHidingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(Config{
		Path: path, SessionID: "s", ServerID: "srv", ImageDigest: "sha256:x",
		Buffer: 1, CheckpointEvery: 1000, CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Far more entries than the queue can hold, faster than the writer
	// can drain them.
	for i := 0; i < 5000; i++ {
		l.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "t", Status: "SUCCESS"}})
	}
	l.Close()

	rep, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("dropping entries must not corrupt the chain: %v", rep.Problems)
	}
	if rep.Gaps == 0 || rep.LostEntries == 0 {
		t.Fatalf("entries were lost to backpressure and the chain must say so: gaps=%d lost=%d (written %d)",
			rep.Gaps, rep.LostEntries, rep.Executions)
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "intact but incomplete") {
		t.Errorf("a gapped chain must be reported as incomplete: %v", rep.Problems)
	}
}

func TestLog_AppendNeverBlocksTheCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(Config{Path: path, SessionID: "s", Buffer: 1, CheckpointInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 20000; i++ {
			l.Append(Entry{Kind: KindExecution, Execution: &Execution{ToolName: "t"}})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Append blocked; §7.1 requires that audit never block the response path")
	}
}

func TestLog_LearningModeIsStampedOnEveryEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(Config{
		Path: path, SessionID: "s", ServerID: "srv", ImageDigest: "sha256:x",
		LearningMode: true, CheckpointInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A caller that forgets to set the flag — or tries to clear it — must
	// not be able to produce an unflagged entry.
	l.Append(Entry{Kind: KindExecution, LearningMode: false, Execution: &Execution{ToolName: "t"}})
	l.Close()

	entries, err := Tail(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	for _, e := range entries {
		if !e.LearningMode {
			t.Fatalf("entry %s is not flagged as learning mode; an unconfined execution that does not say so is the exact thing CLAUDE.md forbids", e.EntryID)
		}
	}
	rep, _ := Verify(path)
	if rep.LearningRuns != len(entries) {
		t.Errorf("verify counted %d learning entries of %d", rep.LearningRuns, len(entries))
	}
}

func TestHashPayload_DoesNotStoreTheBody(t *testing.T) {
	h := HashPayload([]byte(`{"secret":"hunter2"}`))
	if strings.Contains(h, "hunter2") {
		t.Fatalf("the audit log must record a digest, never the payload: %q", h)
	}
	if HashPayload(nil) != "" {
		t.Errorf("an empty payload should hash to nothing, not to the empty-string digest")
	}
}

func TestVerify_EmptyAndMissingChains(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(empty, nil, 0o600)
	rep, err := Verify(empty)
	if err != nil || !rep.Valid || rep.Entries != 0 {
		t.Fatalf("an empty chain is vacuously valid: %+v %v", rep, err)
	}
	if _, err := Verify(filepath.Join(dir, "nope.jsonl")); err == nil {
		t.Errorf("verifying a missing chain must be an error, not a pass")
	}
}
