package analyze

import (
	"fmt"
	"testing"
	"time"

	"mcp-warden/sandbox/profile"
)

// The cases in this file all come from one real run: the official
// @modelcontextprotocol/server-everything package, confined under gVisor
// and analysed by this engine. That run reported QUARANTINE with three
// kernel-attested findings before serving a single request, and every one
// of them was wrong. They are regression tests because each was a
// different way of confusing warden's own machinery, or the runtime's,
// with behaviour of the server under test — and a security tool that
// cries wolf on a healthy server is one whose findings stop being read.

// nodeProfile approximates what learning mode generates for a real Node
// server: individual files granted inside a dependency tree, no
// directories.
func nodeProfile() *profile.CapabilityProfile {
	return &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
		GeneratedBy:    "learning_mode",
		ApprovedBy:     "operator:test",
		Tools: []profile.Tool{{
			Name:     "everything",
			Effects:  []profile.Effect{profile.EffectRead},
			Syscalls: []string{"read", "write", "openat", "close", "newfstatat", "mmap", "futex", "execve"},
			Filesystem: profile.FilesystemAccess{
				Read: []string{
					"/usr/bin/node",
					"/app/node_modules/pkg/dist/index.js",
					"/app/node_modules/pkg/dist/tools/echo.js",
				},
			},
			MaxDurationMS: 5000,
		}},
	}
}

func TestNoFalsePositive_CanaryShimIsNotTheWorkload(t *testing.T) {
	// warden's canary shim deliberately attempts a forbidden syscall
	// inside every container to prove the seccomp filter is live, then
	// execs the real server. Counting that against the server's profile
	// made every single container report a confinement gap.
	e, c := newTestEngine(t, BaselineFromProfile(nodeProfile()))
	e.SetPipelineStats(mockTailStats(1000, 0), true)
	e.SetEntrypoint(EntrypointIdentity{Path: "/usr/bin/node", SHA256: "sha256:node"})

	probeCanary := evErr(c.now(), 1, "reboot", `0xfee1dead, 0x28121969`, 1, "operation not permitted")
	probeCanary.Process = "probe"
	e.Ingest(probeCanary)

	probeExec := ev(c.now(), 1, "execve", `0x1 /usr/bin/node`, 0)
	probeExec.Process = "probe"
	e.Ingest(probeExec)

	for _, f := range securityFindings(e.Evaluate()) {
		t.Errorf("canary shim produced a finding about the server: %s", f)
	}
}

func TestNoFalsePositive_SandboxProvidedPathsAreNotDrift(t *testing.T) {
	// Every language runtime reads /proc and /sys at startup. A profile
	// structurally cannot declare those — the generator filters them —
	// so reporting them as undeclared reads is a finding no profile could
	// ever clear.
	e, c := newTestEngine(t, BaselineFromProfile(nodeProfile()))
	e.SetPipelineStats(mockTailStats(1000, 0), true)

	for _, p := range []string{
		"/proc/meminfo", "/proc/self/maps", "/proc/self/cgroup",
		"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size",
		"/dev/null",
	} {
		e.Ingest(ev(c.now(), 1, "openat", fmt.Sprintf(`AT_FDCWD /, 0x1 %s, O_RDONLY|0x0, 0o0`, p), 7))
		e.Ingest(ev(c.now(), 1, "read", `0x7, 0x100, 0x1000`, 128))
		e.Ingest(ev(c.now(), 1, "close", `0x7`, 0))
	}

	for _, f := range securityFindings(e.Evaluate()) {
		t.Errorf("sandbox-provided path produced a finding: %s", f)
	}
}

func TestNoFalsePositive_DirectoryHoldingGrantedFiles(t *testing.T) {
	// Granting /app/node_modules/pkg/dist/index.js necessarily makes
	// /app/node_modules/pkg/dist exist inside the guest. A server reading
	// that directory is looking at the mount topology warden built for
	// it, and can see nothing there but what the profile granted.
	e, c := newTestEngine(t, BaselineFromProfile(nodeProfile()))
	e.SetPipelineStats(mockTailStats(1000, 0), true)

	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /app/node_modules/pkg/dist, O_RDONLY|0x0, 0o0`, 9))
	e.Ingest(ev(c.now(), 1, "read", `0x9, 0x100, 0x1000`, 64))
	e.Ingest(ev(c.now(), 1, "close", `0x9`, 0))

	for _, f := range securityFindings(e.Evaluate()) {
		t.Errorf("directory holding granted files produced a finding: %s", f)
	}
}

func TestNoFalsePositive_ModuleResolutionProbes(t *testing.T) {
	// A module loader finds a dependency by trying candidate paths until
	// one exists; a reference Node server misses roughly three quarters of
	// its lookups doing nothing but starting up. Reporting that as
	// enumeration or as probing flags every Node server there is.
	e, c := newTestEngine(t, BaselineFromProfile(nodeProfile()))
	e.SetPipelineStats(mockTailStats(5000, 0), true)

	for i := 0; i < 400; i++ {
		e.Ingest(evErr(c.now(), 1,
			"openat",
			fmt.Sprintf(`AT_FDCWD /, 0x1 /app/node_modules/pkg/dist/candidate%d/package.json, O_RDONLY|0x0, 0o0`, i),
			2, "no such file or directory"))
		c.advance(time.Microsecond)
	}

	for _, f := range securityFindings(e.Evaluate()) {
		t.Errorf("module resolution produced a finding: %s", f)
	}
}

func TestDeniedSyscallIsRefusedNotSucceeded(t *testing.T) {
	// The counterpart to the parser fix: a syscall outside the profile
	// that the kernel refused is confinement working, reported as high.
	// The same syscall *succeeding* is a confinement gap, reported as
	// critical. Before the strace parser read error results correctly,
	// every denial landed in the second bucket.
	e, c := newTestEngine(t, BaselineFromProfile(nodeProfile()), SyscallDrift{})
	e.Ingest(evErr(c.now(), 1, "ptrace", `0x10, 0x1`, 1, "operation not permitted"))

	findings := e.Evaluate()
	if len(findings) != 1 {
		t.Fatalf("want exactly one finding, got %d: %+v", len(findings), findings)
	}
	if got := findings[0].Key; got != "syscall-drift:refused" {
		t.Fatalf("a denied syscall must report as refused, got %q (severity %s)", got, findings[0].Severity)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %s, want high (critical is reserved for a syscall that succeeded)", findings[0].Severity)
	}
}
