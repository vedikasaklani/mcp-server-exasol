package violation_test

import (
	"strings"
	"testing"

	"mcp-warden/sandbox/violation"
)

func TestDenialError_SeccompMessageNamesTheSyscall(t *testing.T) {
	err := &violation.DenialError{
		RequestID: "req_123",
		Event:     violation.Event{Kind: violation.DenialKindSeccomp, Syscall: "ptrace", Errno: 1},
	}
	msg := err.Error()
	if !strings.Contains(msg, "req_123") || !strings.Contains(msg, "ptrace") {
		t.Fatalf("error message not diagnosable: %q", msg)
	}
}

func TestDenialError_LandlockMessageNamesThePath(t *testing.T) {
	err := &violation.DenialError{
		RequestID: "req_456",
		Event:     violation.Event{Kind: violation.DenialKindLandlock, Path: "/etc/shadow", Errno: 13},
	}
	msg := err.Error()
	if !strings.Contains(msg, "req_456") || !strings.Contains(msg, "/etc/shadow") {
		t.Fatalf("error message not diagnosable: %q", msg)
	}
}

func TestCorrelationStore_StampLookupClear(t *testing.T) {
	s := violation.NewCorrelationStore()

	if _, ok := s.Lookup("cg_1"); ok {
		t.Fatalf("expected no mapping before Stamp")
	}

	s.Stamp("cg_1", "req_a")
	got, ok := s.Lookup("cg_1")
	if !ok || got != "req_a" {
		t.Fatalf("Lookup after Stamp = (%q, %v), want (req_a, true)", got, ok)
	}

	s.Clear("cg_1")
	if _, ok := s.Lookup("cg_1"); ok {
		t.Fatalf("expected mapping to be gone after Clear")
	}
}

func TestCorrelationStore_RestampOverwritesPreviousRequest(t *testing.T) {
	s := violation.NewCorrelationStore()
	s.Stamp("cg_1", "req_a")
	s.Stamp("cg_1", "req_b")

	got, ok := s.Lookup("cg_1")
	if !ok || got != "req_b" {
		t.Fatalf("Lookup = (%q, %v), want (req_b, true) — a stale mapping must never win", got, ok)
	}
}

func TestCorrelationStore_DistinctCgroupsDoNotCollide(t *testing.T) {
	s := violation.NewCorrelationStore()
	s.Stamp("cg_1", "req_a")
	s.Stamp("cg_2", "req_b")

	if got, _ := s.Lookup("cg_1"); got != "req_a" {
		t.Fatalf("cg_1 = %q, want req_a", got)
	}
	if got, _ := s.Lookup("cg_2"); got != "req_b" {
		t.Fatalf("cg_2 = %q, want req_b", got)
	}
}
