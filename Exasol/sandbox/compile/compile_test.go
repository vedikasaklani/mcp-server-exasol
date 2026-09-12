package compile

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/profile"
)

func sampleTool() profile.Tool {
	return profile.Tool{
		Name:       "query_metrics",
		Syscalls:   []string{"read", "write", "openat", "connect", "socket"},
		Filesystem: profile.FilesystemAccess{Read: []string{"/app", "/etc/ssl"}, Write: []string{"/tmp/scratch"}},
		Network:    []profile.NetworkDestination{{Host: "db.internal", Port: 5432, Proto: "tcp"}},
	}
}

func TestCompileSeccomp_DefaultDenyIsErrnoEPERM(t *testing.T) {
	cp, err := Tool(sampleTool(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Seccomp.DefaultAction != specs.ActErrno {
		t.Fatalf("default action = %v, want %v (default-deny, not fail-open)", cp.Seccomp.DefaultAction, specs.ActErrno)
	}
	if cp.Seccomp.DefaultErrnoRet == nil || *cp.Seccomp.DefaultErrnoRet != errnoEPERM {
		t.Fatalf("default errno = %v, want EPERM per CLAUDE.md non-negotiable (not SIGSYS)", cp.Seccomp.DefaultErrnoRet)
	}
}

func TestCompileSeccomp_AllowsExactlyDeclaredSyscalls(t *testing.T) {
	tool := sampleTool()
	cp, err := Tool(tool, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cp.Seccomp.Syscalls) != 1 {
		t.Fatalf("expected exactly one allow entry, got %d", len(cp.Seccomp.Syscalls))
	}
	entry := cp.Seccomp.Syscalls[0]
	if entry.Action != specs.ActAllow {
		t.Fatalf("entry action = %v, want SCMP_ACT_ALLOW", entry.Action)
	}
	got := map[string]bool{}
	for _, n := range entry.Names {
		got[n] = true
	}
	for _, want := range tool.Syscalls {
		if !got[want] {
			t.Errorf("declared syscall %q missing from compiled allowlist", want)
		}
	}
	if len(got) != len(tool.Syscalls) {
		t.Errorf("compiled allowlist has %d unique syscalls, profile declared %d", len(got), len(tool.Syscalls))
	}
}

func TestCompileSeccomp_DedupesSyscalls(t *testing.T) {
	tool := sampleTool()
	tool.Syscalls = append(tool.Syscalls, "read", "read")
	cp, err := Tool(tool, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	for _, n := range cp.Seccomp.Syscalls[0].Names {
		if n == "read" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 'read' to appear exactly once in compiled allowlist, got %d", count)
	}
}

func TestCompileSeccomp_RejectsEmptySyscallList(t *testing.T) {
	tool := sampleTool()
	tool.Syscalls = nil
	if _, err := Tool(tool, Options{}); err == nil {
		t.Fatalf("expected error compiling a tool with no allowed syscalls")
	}
}

func TestCompileSeccomp_RejectsCanarySyscall(t *testing.T) {
	tool := sampleTool()
	tool.Syscalls = append(tool.Syscalls, CanarySyscall)
	_, err := Tool(tool, Options{})
	if err == nil || !strings.Contains(err.Error(), "canary") {
		t.Fatalf("expected canary-syscall rejection, got %v", err)
	}
}

func TestCompileLandlock_SeparatesReadAndWrite(t *testing.T) {
	cp, err := Tool(sampleTool(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byPath := map[string]LandlockAccess{}
	for _, r := range cp.Landlock.Rules {
		byPath[r.Path] = r.Access
	}
	if byPath["/app"] != AccessRead {
		t.Errorf("/app access = %v, want AccessRead only", byPath["/app"])
	}
	if byPath["/tmp/scratch"] != AccessWrite {
		t.Errorf("/tmp/scratch access = %v, want AccessWrite only", byPath["/tmp/scratch"])
	}
	if cp.Landlock.AppliesTo != LandlockTargetGuest {
		t.Errorf("AppliesTo = %v, want %v (see design note flag #2 for why this is still open)", cp.Landlock.AppliesTo, LandlockTargetGuest)
	}
}

func TestCompileLandlock_EmptyFilesystemIsNotAnError(t *testing.T) {
	tool := sampleTool()
	tool.Filesystem = profile.FilesystemAccess{}
	cp, err := Tool(tool, Options{})
	if err != nil {
		t.Fatalf("a network-only tool with no filesystem access must compile cleanly, got %v", err)
	}
	if len(cp.Landlock.Rules) != 0 {
		t.Fatalf("expected zero landlock rules, got %d", len(cp.Landlock.Rules))
	}
}

func TestCompileNetwork_NoInterfacesEverGranted(t *testing.T) {
	cp, err := Tool(sampleTool(), Options{BrokerSocketPath: "/run/warden/broker.sock"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cp.Network.Mode != NetworkModeNone {
		t.Fatalf("network mode = %q, want %q — v0 never grants a sandbox a real network interface", cp.Network.Mode, NetworkModeNone)
	}
	if cp.Network.BrokerSocketPath != "/run/warden/broker.sock" {
		t.Fatalf("broker socket path not threaded through: got %q", cp.Network.BrokerSocketPath)
	}
	if len(cp.Network.AllowedDestinations) != 1 || cp.Network.AllowedDestinations[0].Host != "db.internal" {
		t.Fatalf("unexpected allowed destinations: %+v", cp.Network.AllowedDestinations)
	}
}

func TestCompileProfile_OneBadToolFailsTheWholeProfile(t *testing.T) {
	good := sampleTool()
	bad := sampleTool()
	bad.Name = "broken_tool"
	bad.Syscalls = nil

	p := &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:" + strings.Repeat("a", 64),
		GeneratedBy:    "learning_mode",
		ApprovedBy:     "operator:neal",
		Tools:          []profile.Tool{good, bad},
	}

	if _, err := Profile(p, Options{}); err == nil {
		t.Fatalf("expected profile compilation to fail when any single tool fails to compile")
	}
}

func TestCompileProfile_CompilesAllTools(t *testing.T) {
	toolA := sampleTool()
	toolB := sampleTool()
	toolB.Name = "other_tool"

	p := &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:" + strings.Repeat("a", 64),
		GeneratedBy:    "learning_mode",
		ApprovedBy:     "operator:neal",
		Tools:          []profile.Tool{toolA, toolB},
	}

	compiled, err := Profile(p, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("expected 2 compiled policies, got %d", len(compiled))
	}
	if _, ok := compiled["query_metrics"]; !ok {
		t.Errorf("missing compiled policy for query_metrics")
	}
	if _, ok := compiled["other_tool"]; !ok {
		t.Errorf("missing compiled policy for other_tool")
	}
}
