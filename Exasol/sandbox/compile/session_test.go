package compile

import (
	"strings"
	"testing"

	"mcp-warden/sandbox/profile"
)

func twoToolProfile() *profile.CapabilityProfile {
	return &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:" + strings.Repeat("a", 64),
		GeneratedBy:    "learning_mode",
		ApprovedBy:     "operator:neal",
		Tools: []profile.Tool{
			{
				Name:       "query_metrics",
				Syscalls:   []string{"read", "openat", "connect"},
				Filesystem: profile.FilesystemAccess{Read: []string{"/app"}},
				Network:    []profile.NetworkDestination{{Host: "db.internal", Port: 5432, Proto: "tcp"}},
			},
			{
				Name:       "write_report",
				Syscalls:   []string{"write", "openat"},
				Filesystem: profile.FilesystemAccess{Write: []string{"/tmp/scratch"}},
			},
		},
	}
}

func TestSession_UnionsSyscallsAcrossTools(t *testing.T) {
	cp, err := Session(twoToolProfile(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := map[string]bool{}
	for _, n := range cp.Seccomp.Syscalls[0].Names {
		got[n] = true
	}
	for _, want := range []string{"read", "openat", "connect", "write"} {
		if !got[want] {
			t.Errorf("expected unioned syscall %q, missing from %v", want, cp.Seccomp.Syscalls[0].Names)
		}
	}
	// openat is declared by both tools; must appear exactly once.
	count := 0
	for _, n := range cp.Seccomp.Syscalls[0].Names {
		if n == "openat" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("openat appears %d times in union, want 1", count)
	}
}

func TestSession_UnionsFilesystemAccess(t *testing.T) {
	cp, err := Session(twoToolProfile(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byPath := map[string]LandlockAccess{}
	for _, r := range cp.Landlock.Rules {
		byPath[r.Path] = r.Access
	}
	if byPath["/app"] != AccessRead {
		t.Errorf("/app = %v, want AccessRead", byPath["/app"])
	}
	if byPath["/tmp/scratch"] != AccessWrite {
		t.Errorf("/tmp/scratch = %v, want AccessWrite", byPath["/tmp/scratch"])
	}
}

func TestSession_MergesReadAndWriteOnSamePath(t *testing.T) {
	p := twoToolProfile()
	// Both tools now touch /shared, one for read and one for write — the
	// union must grant both bits on that single path, not just the last
	// one processed.
	p.Tools[0].Filesystem.Read = append(p.Tools[0].Filesystem.Read, "/shared")
	p.Tools[1].Filesystem.Write = append(p.Tools[1].Filesystem.Write, "/shared")

	cp, err := Session(p, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got LandlockAccess
	for _, r := range cp.Landlock.Rules {
		if r.Path == "/shared" {
			got = r.Access
		}
	}
	if got != AccessRead|AccessWrite {
		t.Fatalf("/shared access = %v, want AccessRead|AccessWrite", got)
	}
}

func TestSession_UnionsNetworkDestinationsAndDedupes(t *testing.T) {
	p := twoToolProfile()
	p.Tools[1].Network = append(p.Tools[1].Network, profile.NetworkDestination{Host: "db.internal", Port: 5432, Proto: "tcp"})

	cp, err := Session(p, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cp.Network.AllowedDestinations) != 1 {
		t.Fatalf("expected the duplicate destination to be deduped, got %+v", cp.Network.AllowedDestinations)
	}
}

func TestSession_ToolNamesCoversWholeProfile(t *testing.T) {
	cp, err := Session(twoToolProfile(), Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cp.ToolNames) != 2 {
		t.Fatalf("ToolNames = %v, want both tools", cp.ToolNames)
	}
}

func TestSession_IsDeterministic(t *testing.T) {
	p := twoToolProfile()
	a, err := Session(p, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := Session(p, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Join(a.Seccomp.Syscalls[0].Names, ",") != strings.Join(b.Seccomp.Syscalls[0].Names, ",") {
		t.Fatalf("two compilations of the same profile produced different syscall orderings")
	}
}

func TestSession_RejectsCanarySyscallFromAnyTool(t *testing.T) {
	p := twoToolProfile()
	p.Tools[1].Syscalls = append(p.Tools[1].Syscalls, CanarySyscall)

	_, err := Session(p, Options{})
	if err == nil || !strings.Contains(err.Error(), "canary") {
		t.Fatalf("expected canary rejection, got %v", err)
	}
}

func TestSession_RejectsEmptyProfile(t *testing.T) {
	p := twoToolProfile()
	p.Tools = nil
	if _, err := Session(p, Options{}); err == nil {
		t.Fatalf("expected error compiling a session policy from zero tools")
	}
}
