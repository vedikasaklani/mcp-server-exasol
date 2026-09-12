package observe

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reportForProfile(t *testing.T, paths []string) *Report {
	t.Helper()
	r := &Report{
		// A non-ELF entrypoint so these path-narrowing tests aren't
		// perturbed by the ELF interpreter that GenerateProfile adds for
		// real dynamically linked binaries (covered separately below).
		Target:   Target{Command: []string{"/nonexistent/entrypoint"}},
		Duration: 2 * time.Second,
		Syscalls: map[string]*SyscallStat{
			"read":   {Syscall: "read", Count: 10},
			"openat": {Syscall: "openat", Count: 5},
			"mmap":   {Syscall: "mmap", Count: 3},
		},
		Paths: map[string]*PathAccess{},
	}
	for _, p := range paths {
		r.Paths[p] = &PathAccess{Path: p, Kind: AccessRead, Count: 1, Syscalls: map[string]int{"openat": 1}}
	}
	return r
}

func TestGenerateProfile_LeavesApprovedByEmptySoItFailsValidation(t *testing.T) {
	r := reportForProfile(t, nil)
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cand.Profile.ApprovedBy != "" {
		t.Fatalf("generated profile must not self-approve (§3.2 never auto-promote), got %q", cand.Profile.ApprovedBy)
	}
	err = cand.Profile.Validate()
	if err == nil || !strings.Contains(err.Error(), "approved_by") {
		t.Fatalf("an unapproved candidate must fail validation on approved_by, got %v", err)
	}

	// And once a human approves it, it becomes valid.
	cand.Profile.ApprovedBy = "operator:test"
	if err := cand.Profile.Validate(); err != nil {
		t.Fatalf("profile should validate once approved, got %v", err)
	}
}

func TestGenerateProfile_ExcludesSandboxProvidedVirtualPaths(t *testing.T) {
	r := reportForProfile(t, []string{"/proc/self/maps", "/sys/devices/system/cpu/online", "/dev/null", "/tmp/scratch/x"})
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fs := cand.Profile.Tools[0].Filesystem
	if len(fs.Read) != 0 || len(fs.Write) != 0 {
		t.Fatalf("virtual paths must not be declared as mountable host paths, got read=%v write=%v", fs.Read, fs.Write)
	}
	if len(cand.SkippedVirtual) != 4 {
		t.Errorf("expected all 4 virtual paths reported as skipped, got %v", cand.SkippedVirtual)
	}
}

func TestGenerateProfile_SkipsPathsThatNoLongerExist(t *testing.T) {
	r := reportForProfile(t, []string{"/definitely/not/a/real/path/xyz"})
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cand.SkippedMissing) != 1 {
		t.Fatalf("expected the missing path to be skipped and reported, got %v", cand.SkippedMissing)
	}
}

func TestGenerateProfile_RollupCollapsesAndReportsWidening(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, name := range []string{"one.js", "two.js", "three.js"} {
		p := filepath.Join(deep, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}

	r := reportForProfile(t, paths)
	// Depth chosen to collapse the three files into their common tree.
	depth := len(strings.Split(strings.TrimPrefix(deep, "/"), "/"))
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv", RollupDepth: depth})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cand.Profile.Tools[0].Filesystem.Read) != 1 {
		t.Fatalf("expected 3 sibling files to roll up to 1 grant, got %v", cand.Profile.Tools[0].Filesystem.Read)
	}
	if len(cand.Widenings) != 1 || cand.Widenings[0].CoveredN != 3 {
		t.Fatalf("rollup must report what it widened for the reviewer, got %+v", cand.Widenings)
	}
}

func TestGenerateProfile_NoRollupKeepsExactPathsAndReportsNoWidening(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cand, err := GenerateProfile(reportForProfile(t, []string{p}), ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cand.Widenings) != 0 {
		t.Fatalf("granting exactly what was observed widens nothing, got %+v", cand.Widenings)
	}
}

func TestGenerateProfile_WritePathsAreOperatorDeclaredNotGuessed(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "code.js")
	if err := os.WriteFile(readable, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := reportForProfile(t, []string{readable})
	// Even though this path was observed with write intent, it is only
	// granted write because the operator declared it.
	r.Paths[readable].Kind = AccessWrite

	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cand.Profile.Tools[0].Filesystem.Write) != 0 {
		t.Fatalf("observed write intent alone must not grant write, got %v", cand.Profile.Tools[0].Filesystem.Write)
	}

	cand, err = GenerateProfile(r, ProfileOptions{ToolName: "srv", WritePaths: []string{dir}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(cand.Profile.Tools[0].Filesystem.Write, readable) && !contains(cand.Profile.Tools[0].Filesystem.Write, dir) {
		t.Fatalf("operator-declared write prefix must be granted, got %v", cand.Profile.Tools[0].Filesystem.Write)
	}
}

func TestGenerateProfile_DeclaredWritePathSurvivesEvenIfNeverObserved(t *testing.T) {
	cand, err := GenerateProfile(reportForProfile(t, nil), ProfileOptions{
		ToolName:   "srv",
		WritePaths: []string{"/var/lib/srv/scratch"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(cand.Profile.Tools[0].Filesystem.Write, "/var/lib/srv/scratch") {
		t.Fatalf("a declared write path must be granted even if profiling never exercised it, got %v",
			cand.Profile.Tools[0].Filesystem.Write)
	}
}

func TestGenerateProfile_CarriesObservedSyscalls(t *testing.T) {
	cand, err := GenerateProfile(reportForProfile(t, nil), ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := cand.Profile.Tools[0].Syscalls
	for _, want := range []string{"read", "openat", "mmap"} {
		if !contains(got, want) {
			t.Errorf("observed syscall %q missing from generated profile: %v", want, got)
		}
	}
}

// The ELF interpreter is the one path a syscall trace can never reveal:
// the kernel maps it inside execve rather than through an openat the guest
// makes. A profile without it produces an execve failing with ENOENT that
// names the binary — which IS mounted — so the mistake looks like anything
// but what it is. This was found by running the pipeline against a real
// Node server.
func TestGenerateProfile_AddsELFInterpreterForDynamicallyLinkedEntrypoint(t *testing.T) {
	// /bin/sh is dynamically linked on every realistic Linux host.
	interp, err := elfInterpreter("/bin/sh")
	if err != nil || interp == "" {
		t.Skipf("/bin/sh has no readable ELF interpreter here (%v); nothing to assert", err)
	}

	r := reportForProfile(t, nil)
	r.Target = Target{Command: []string{"/bin/sh"}}

	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(cand.Profile.Tools[0].Filesystem.Read, interp) {
		t.Fatalf("ELF interpreter %q must be granted, got %v", interp, cand.Profile.Tools[0].Filesystem.Read)
	}
	if !contains(cand.AddedForExec, interp) {
		t.Fatalf("adding an unobserved path must be reported, got %v", cand.AddedForExec)
	}
}

func TestGenerateProfile_AddsNothingForAStaticEntrypoint(t *testing.T) {
	r := reportForProfile(t, nil)
	// A path that isn't an ELF file at all yields no interpreter.
	r.Target = Target{Command: []string{"/nonexistent/entrypoint"}}
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cand.AddedForExec) != 0 {
		t.Fatalf("expected no exec-required additions, got %v", cand.AddedForExec)
	}
}

func TestGenerateProfile_RejectsEmptyReport(t *testing.T) {
	if _, err := GenerateProfile(&Report{Syscalls: map[string]*SyscallStat{}}, ProfileOptions{}); err == nil {
		t.Fatalf("expected an error generating a profile from zero observations")
	}
	if _, err := GenerateProfile(nil, ProfileOptions{}); err == nil {
		t.Fatalf("expected an error on a nil report")
	}
}

func TestGenerateProfile_DigestIsStableAndBoundToTheArtifact(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "server.js")
	if err := os.WriteFile(script, []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := reportForProfile(t, nil)
	r.Target = Target{Command: []string{"/bin/sh", script}}

	a, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Profile.ImageDigest != b.Profile.ImageDigest {
		t.Fatalf("digest must be stable across runs: %s vs %s", a.Profile.ImageDigest, b.Profile.ImageDigest)
	}

	// Changing the artifact changes the digest, so a modified server
	// cannot inherit an approved profile.
	if err := os.WriteFile(script, []byte("console.log(2)"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := GenerateProfile(r, ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile.ImageDigest == a.Profile.ImageDigest {
		t.Fatalf("a modified artifact must not keep the same digest")
	}
}

func TestGenerateProfile_PinsTheEntrypointAndItsInterpreter(t *testing.T) {
	// A real, dynamically linked binary that is present on any system
	// this project targets.
	bin, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	r := &Report{
		Target:   Target{Command: []string{bin}},
		Syscalls: map[string]*SyscallStat{"read": {Syscall: "read", Count: 1}},
		Paths:    map[string]*PathAccess{},
	}
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "t", ImageDigest: "sha256:x"})
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}
	ep := cand.Profile.Entrypoint
	if ep == nil || ep.SHA256 == "" {
		t.Fatalf("the entrypoint must be pinned by digest: %+v", ep)
	}
	if ep.Path != bin {
		t.Errorf("pinned path = %q, want %q", ep.Path, bin)
	}
	if ep.Interpreter == "" || ep.InterpreterSHA256 == "" {
		t.Errorf("a dynamically linked entrypoint must pin its ELF interpreter too; it appears in no trace and nothing else covers it: %+v", ep)
	}
}

func TestGenerateProfile_MissingEntrypointDoesNotFailGeneration(t *testing.T) {
	r := &Report{
		Target:   Target{Command: []string{"/nonexistent/entrypoint"}},
		Syscalls: map[string]*SyscallStat{"read": {Syscall: "read", Count: 1}},
		Paths:    map[string]*PathAccess{},
	}
	cand, err := GenerateProfile(r, ProfileOptions{ToolName: "t", ImageDigest: "sha256:x"})
	if err != nil {
		t.Fatalf("a binary that cannot be hashed must not fail profile generation: %v", err)
	}
	if cand.Profile.Entrypoint != nil {
		t.Errorf("expected no attestation, got %+v", cand.Profile.Entrypoint)
	}
}
