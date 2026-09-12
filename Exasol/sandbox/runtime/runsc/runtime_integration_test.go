package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/profile"
	"mcp-warden/sandbox/runtime"
)

// shortID derives a short, fixed-length, filesystem-and-socket-safe
// container id from a test name. runsc's default state directory is
// $XDG_RUNTIME_DIR/runsc/<id> (or /var/run/runsc/<id>), and it places a
// control socket at a path derived from <id> — a long id (e.g. a full
// "Test.../subtest_name" string) pushes that path past AF_UNIX's 108-byte
// sun_path limit and runsc fails with "unable to find location to write
// socket file". A short hash sidesteps that regardless of how long or
// nested the test name is.
func shortID(prefix, name string) string {
	sum := sha256.Sum256([]byte(name))
	return prefix + "-" + hex.EncodeToString(sum[:4])
}

// This file is the empirical answer to design note flags #2 and #3: does
// runsc actually enforce an OCI-spec seccomp policy against the workload
// with the expected errno, and does a Landlock ruleset do anything
// meaningful to a process running inside a gVisor guest. It requires a
// real `runsc` on PATH and, in this environment, real root (rootless
// needs setuid newuidmap/newgidmap and cgroup delegation that aren't set
// up here) — run it with:
//
//	sudo go test ./sandbox/runtime/runsc/... -run Integration -v
//
// Every other test in this package runs unprivileged and is exercised by
// the normal `go test ./...`; this file skips itself out of that run.

var probeBinPath string

func TestMain(m *testing.M) {
	os.Exit(runIntegrationMain(m))
}

func runIntegrationMain(m *testing.M) int {
	if _, err := exec.LookPath("runsc"); err == nil && os.Geteuid() == 0 {
		dir, err := os.MkdirTemp("", "warden-probe-build")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		probeBinPath = filepath.Join(dir, "probe")

		cmd := exec.Command("go", "build", "-o", probeBinPath, "mcp-warden/sandbox/runtime/runsc/probe")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			panic("build probe binary: " + err.Error() + ": " + string(out))
		}
	}
	return m.Run()
}

func requireIntegration(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("runsc"); err != nil {
		t.Skip("runsc not found on PATH; skipping integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("this environment's runsc needs real root (rootless needs setuid newuidmap/newgidmap and cgroup delegation not set up here) — run with: sudo go test ./sandbox/runtime/runsc/... -run Integration -v")
	}
}

// goRuntimeBaselineSyscalls is what a statically-linked Go binary needs
// just to start and run a goroutine scheduler on linux/amd64 — mmap,
// futex, clone, signal handling, epoll for the netpoller, and so on. A
// CapabilityProfile's declared syscalls (§8.2) are meant to describe
// application-level capability (file access, network, exec), not this
// runtime mechanics layer; in a real deployment this baseline is exactly
// what learning mode's observation would capture automatically (§3.2 step
// 3), since it watches everything a real execution actually does.
//
// This project doesn't yet have that observation tooling built (see the
// gap noted in the "next step" summary), so for this hand-written
// integration-test profile the baseline is listed explicitly, from
// documented Go runtime behavior rather than an empirical strace capture
// (strace isn't installed in this dev environment either). It should be
// treated as a reasonable starting point to verify against once tracing
// is available, not a certified-minimal set.
var goRuntimeBaselineSyscalls = []string{
	"read", "write", "close", "fstat", "newfstatat", "lseek",
	"mmap", "mprotect", "munmap", "madvise", "brk",
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
	"arch_prctl", "gettid", "getpid", "futex", "futex_waitv",
	"sched_getaffinity", "sched_yield",
	"clone", "clone3", "exit", "exit_group",
	"epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "pipe2",
	"tgkill", "nanosleep", "clock_gettime", "clock_nanosleep",
	"getrandom", "uname", "prlimit64",
	"set_tid_address", "set_robust_list", "rseq",
	"execve", "fcntl", "ioctl", "readlinkat", "access",
}

func testPolicy(t *testing.T, extraSyscalls []string, fs profile.FilesystemAccess) *compile.CompiledPolicy {
	t.Helper()
	p := &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:" + strings.Repeat("a", 64),
		GeneratedBy:    "integration_test",
		ApprovedBy:     "operator:test",
		Tools: []profile.Tool{{
			Name:          "integration_probe",
			Syscalls:      append(append([]string{}, goRuntimeBaselineSyscalls...), extraSyscalls...),
			Filesystem:    fs,
			MaxDurationMS: 30000,
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("test profile invalid: %v", err)
	}
	cp, err := compile.Session(p, compile.Options{})
	if err != nil {
		t.Fatalf("compile.Session: %v", err)
	}
	return cp
}

// shortTempDir returns a fresh temp directory under /tmp with a short,
// fixed-length name, cleaned up when t ends. Go's t.TempDir() nests
// directories under the full (possibly long, "/"-containing-turned-"-")
// subtest name, and runsc places a control socket at a path derived from
// the bundle directory — long enough, that exceeds AF_UNIX's 108-byte
// sun_path limit and runsc fails with "unable to find location to write
// socket file". Short, flat paths avoid that entirely.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "warden-it-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newTestRuntime(t *testing.T, args []string) (*Runtime, string) {
	t.Helper()
	id := shortID("it", t.Name())
	return &Runtime{
		BundleRoot:      shortTempDir(t),
		Rootfs:          BundleConfig{RootfsPath: shortTempDir(t), Args: args},
		ProbeBinaryPath: probeBinPath,
	}, id
}

// TestIntegration_CanaryIsDeniedAndWorkloadRuns is the central spike: it
// exercises the real Runtime.Create -> ProbeSyscall -> Exec -> Destroy
// path end to end, and specifically confirms design note flag #3 — that
// runsc enforces the OCI seccomp policy this project compiles against the
// actual workload, with the exact errno CLAUDE.md requires (EPERM, not
// SIGSYS/ENOSYS), and that the canary shim's fail-closed gate still lets
// a properly-confined workload run normally afterward.
func TestIntegration_CanaryIsDeniedAndWorkloadRuns(t *testing.T) {
	requireIntegration(t)

	policy := testPolicy(t, nil, profile.FilesystemAccess{})
	rt, id := newTestRuntime(t, []string{ProbeMountPath, "echo"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := rt.Create(ctx, id, policy); err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer rt.Destroy(context.Background(), id)

	denial, err := rt.ProbeSyscall(ctx, id, compile.CanarySyscall)
	if err != nil {
		t.Fatalf("ProbeSyscall: %v", err)
	}
	if !denial.Occurred {
		t.Fatalf("FLAG #3 RESULT: canary syscall was NOT denied — runsc did not enforce the OCI seccomp policy against the workload as this project's design assumes")
	}
	if denial.Errno != 1 {
		t.Fatalf("FLAG #3 RESULT: canary syscall was denied with errno %d, want EPERM (1)", denial.Errno)
	}
	t.Logf("FLAG #3 RESOLVED: runsc enforced the compiled OCI seccomp policy against the workload; canary denied with EPERM as expected")

	res, err := rt.Exec(ctx, id, runtime.ExecRequest{RequestID: "req_it_1", ToolName: "integration_probe", Payload: []byte("hello")})
	if err != nil {
		t.Fatalf("Exec after successful canary: %v", err)
	}
	if !strings.Contains(string(res.Payload), "hello") {
		t.Fatalf("Exec response = %q, want it to echo back the request", res.Payload)
	}
}

// TestIntegration_MountConfinementDeniesUndeclaredPath answers design note
// flag #2 for the mechanism this project actually relies on for
// filesystem confinement: gVisor mounts, not Landlock. A path never
// declared in the profile (and therefore never mounted) must be invisible
// to the guest.
func TestIntegration_MountConfinementDeniesUndeclaredPath(t *testing.T) {
	requireIntegration(t)

	allowedDir := t.TempDir()
	allowedFile := filepath.Join(allowedDir, "allowed.txt")
	if err := os.WriteFile(allowedFile, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	undeclaredDir := t.TempDir()
	undeclaredFile := filepath.Join(undeclaredDir, "secret.txt")
	if err := os.WriteFile(undeclaredFile, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := testPolicy(t, []string{"openat", "connect", "socket"}, profile.FilesystemAccess{Read: []string{allowedFile}})

	t.Run("declared_path_is_readable", func(t *testing.T) {
		out, exitErr := runOneShot(t, policy, []string{ProbeMountPath, "open", allowedFile, "r"})
		t.Logf("probe output: %s", out)
		if exitErr != nil {
			t.Fatalf("expected the shim to gate on canary success and run the workload, got: %v", exitErr)
		}
		if !strings.Contains(out, `"ok":true`) {
			t.Fatalf("expected declared path to be readable, got %q", out)
		}
	})

	t.Run("undeclared_path_is_invisible", func(t *testing.T) {
		out, exitErr := runOneShot(t, policy, []string{ProbeMountPath, "open", undeclaredFile, "r"})
		t.Logf("probe output: %s", out)
		// The canary shim's handshake line must be present regardless of
		// what the open attempt finds — its absence means runsc failed to
		// even start the sandbox, which must not be mistaken for "access
		// was denied."
		if !strings.Contains(out, compile.CanarySyscall) && !strings.Contains(out, `"errno_name"`) {
			t.Fatalf("no canary handshake line found in output — runsc likely failed to start the sandbox rather than denying access; exitErr=%v, out=%q", exitErr, out)
		}
		if strings.Contains(out, `"ok":true`) {
			t.Fatalf("FLAG #2 RESULT: an undeclared path was readable from inside the guest — mount-based confinement did not hold: %q", out)
		}
		t.Logf("FLAG #2 RESOLVED (mount confinement): undeclared path was not accessible from inside the guest")
	})
}

// TestIntegration_LandlockSelfApplyInsideGuest is the direct empirical
// test of design note flag #2's open question: does an LSM restriction
// self-applied by a process running inside a gVisor guest have any
// effect, or is it a no-op because the sentry mediates file syscalls
// itself rather than passing them to a real host VFS for Landlock to see.
//
// This does NOT gate any of this project's actual enforcement (which
// relies on mounts, per GenerateSpec's doc comment) — it exists purely to
// convert that open question into a recorded, checked answer instead of a
// standing assumption.
func TestIntegration_LandlockSelfApplyInsideGuest(t *testing.T) {
	requireIntegration(t)

	allowedDir := t.TempDir()
	allowedFile := filepath.Join(allowedDir, "allowed.txt")
	if err := os.WriteFile(allowedFile, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Both paths are mounted (both declared to gVisor) so that a
	// difference in outcome between them can only be attributed to the
	// probe's own self-applied Landlock rule, not to gVisor's mount-based
	// confinement (which is deliberately not the thing under test here).
	deniedDir := t.TempDir()
	deniedFile := filepath.Join(deniedDir, "denied.txt")
	if err := os.WriteFile(deniedFile, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}

	policy := testPolicy(t, []string{"openat", "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "prctl"},
		profile.FilesystemAccess{Read: []string{allowedFile, deniedFile}})

	out, _ := runOneShot(t, policy, []string{ProbeMountPath, "landlock-selftest", allowedFile, deniedFile})
	t.Logf("probe output:\n%s", out)

	allLines := strings.Split(strings.TrimSpace(out), "\n")
	if len(allLines) < 1 {
		t.Fatalf("expected at least one outcome line, got none")
	}
	// allLines[0] is the canary shim's own handshake line (runOneShot
	// always wraps with the shim), printed before it execs into the
	// landlock-selftest command itself — see probe/main.go's cmdInit.
	// Everything from here on is landlock-selftest's own output.
	lines := allLines[1:]
	if len(lines) < 1 {
		t.Fatalf("expected at least one outcome line from landlock-selftest after the canary handshake, got only: %q", out)
	}
	if strings.Contains(lines[0], `"detail":"landlock self-apply failed`) {
		t.Logf("FLAG #2 RESULT (landlock self-apply): the probe could not self-apply a Landlock ruleset inside the gVisor guest at all: %s", lines[0])
		return
	}
	if len(lines) < 2 {
		t.Fatalf("expected two outcome lines (allow-path, deny-path) after a successful self-apply, got: %q", out)
	}
	allowOK := strings.Contains(lines[0], `"ok":true`)
	denyOK := strings.Contains(lines[1], `"ok":true`)
	switch {
	case allowOK && !denyOK:
		t.Logf("FLAG #2 RESOLVED (landlock self-apply): Landlock self-restriction IS enforced inside a gVisor guest — allowed path readable, denied path blocked")
	case allowOK && denyOK:
		t.Logf("FLAG #2 RESULT (landlock self-apply): Landlock self-restriction had NO effect inside the gVisor guest — both paths remained readable despite the ruleset denying one")
	default:
		t.Logf("FLAG #2 RESULT (landlock self-apply): unexpected outcome, allow=%v deny=%v — needs manual inspection: %s", allowOK, denyOK, out)
	}
}

// runOneShot writes a bundle for a non-interactive workload (one that
// runs to completion and exits, unlike the persistent echo-loop server
// Runtime.Exec talks to) and runs it directly via `runsc run`, capturing
// its combined output. Used by tests that don't need the full
// create/probe/exec/destroy lifecycle, just "did this one-shot command's
// output say what we expect."
func runOneShot(t *testing.T, policy *compile.CompiledPolicy, realArgs []string) (string, error) {
	t.Helper()
	spec, err := GenerateSpec(policy, BundleConfig{
		RootfsPath:         shortTempDir(t),
		Args:               realArgs,
		ProbeBinaryPath:    probeBinPath,
		WrapWithCanaryShim: true,
	})
	if err != nil {
		t.Fatalf("GenerateSpec: %v", err)
	}

	dir := shortTempDir(t)
	cfgBytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfgBytes, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	id := shortID("oneshot", t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, "runsc", "run", "--bundle", dir, id).CombinedOutput()
	_ = exec.Command("runsc", "delete", "--force", id).Run()
	return string(out), runErr
}
