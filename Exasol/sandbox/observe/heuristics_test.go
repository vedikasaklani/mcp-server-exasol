package observe

import (
	"strings"
	"testing"
	"time"
)

func reportWithPaths(paths map[string]AccessKind) *Report {
	r := &Report{Syscalls: map[string]*SyscallStat{}, Paths: map[string]*PathAccess{}}
	for p, kind := range paths {
		r.Paths[p] = &PathAccess{Path: p, Kind: kind, Count: 1, Syscalls: map[string]int{"openat": 1}}
	}
	return r
}

func TestSensitivePathHeuristic_DoesNotFlagOrdinaryHomePaths(t *testing.T) {
	r := reportWithPaths(map[string]AccessKind{
		"/home/neal/mcp-test-servers/node_modules/zod/index.js": AccessRead,
		"/home/neal/project/server.js":                          AccessRead,
	})
	findings := SensitivePathHeuristic{}.Evaluate(r)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for ordinary paths under /home, got %d: %+v", len(findings), findings)
	}
}

func TestSensitivePathHeuristic_FlagsCredentialPaths(t *testing.T) {
	r := reportWithPaths(map[string]AccessKind{
		"/home/neal/.ssh/id_rsa":      AccessRead,
		"/home/neal/.aws/credentials": AccessRead,
		"/etc/shadow":                 AccessRead,
	})
	findings := SensitivePathHeuristic{}.Evaluate(r)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}
}

func TestDangerousSyscallHeuristic_FlagsKnownDangerousCalls(t *testing.T) {
	r := &Report{Syscalls: map[string]*SyscallStat{
		"ptrace": {Syscall: "ptrace", Count: 2},
		"read":   {Syscall: "read", Count: 100},
	}, Paths: map[string]*PathAccess{}}

	findings := DangerousSyscallHeuristic{}.Evaluate(r)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (ptrace only), got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "ptrace") {
		t.Errorf("finding message = %q, want it to name ptrace", findings[0].Message)
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %v, want critical", findings[0].Severity)
	}
}

func TestHighErrorRateHeuristic_IgnoresLowSampleCounts(t *testing.T) {
	r := &Report{Syscalls: map[string]*SyscallStat{
		"openat": {Syscall: "openat", Count: 2, ErrorCount: 2, ErrnosSeen: map[string]int{"ENOENT": 2}},
	}, Paths: map[string]*PathAccess{}}

	findings := HighErrorRateHeuristic{Threshold: 0.5}.Evaluate(r)
	if len(findings) != 0 {
		t.Fatalf("expected no findings with only 2 samples, got %+v", findings)
	}
}

func TestHighErrorRateHeuristic_FlagsAboveThreshold(t *testing.T) {
	r := &Report{Syscalls: map[string]*SyscallStat{
		"openat": {Syscall: "openat", Count: 10, ErrorCount: 8, ErrnosSeen: map[string]int{"ENOENT": 8}},
	}, Paths: map[string]*PathAccess{}}

	findings := HighErrorRateHeuristic{Threshold: 0.5}.Evaluate(r)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
}

func TestSlowSyscallHeuristic_FlagsAboveThreshold(t *testing.T) {
	r := &Report{Syscalls: map[string]*SyscallStat{
		"futex": {Syscall: "futex", Count: 5, MaxTime: 200 * time.Millisecond},
		"read":  {Syscall: "read", Count: 5, MaxTime: time.Microsecond},
	}, Paths: map[string]*PathAccess{}}

	findings := SlowSyscallHeuristic{Threshold: 50 * time.Millisecond}.Evaluate(r)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (futex only), got %d: %+v", len(findings), findings)
	}
}

func TestEvaluate_StampsHeuristicName(t *testing.T) {
	r := &Report{Syscalls: map[string]*SyscallStat{
		"ptrace": {Syscall: "ptrace", Count: 1},
	}, Paths: map[string]*PathAccess{}}

	findings := Evaluate(r, []Heuristic{DangerousSyscallHeuristic{}})
	if len(findings) != 1 || findings[0].Heuristic != "dangerous-syscall" {
		t.Fatalf("expected finding stamped with heuristic name, got %+v", findings)
	}
}

func TestDefaultHeuristics_ReturnsNonEmptySet(t *testing.T) {
	if len(DefaultHeuristics()) == 0 {
		t.Fatalf("expected at least one default heuristic")
	}
}
