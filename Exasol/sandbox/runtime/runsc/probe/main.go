// Command probe is the confined test entrypoint used by sandbox/runtime/runsc's
// integration tests. It exists to answer two questions this project could
// only speculate about from a machine with no runsc install and no 6.1+
// kernel (see the sandbox design note flags #2 and #3): does runsc actually
// enforce an OCI-spec seccomp policy against the *workload* with the
// expected errno, and does a Landlock ruleset do anything meaningful to a
// process running inside a gVisor guest.
//
// It is built as a static binary (CGO_ENABLED=0) so it has no dynamic
// library dependencies and can run from a minimal rootfs containing
// nothing but this binary.
//
// SAFETY: the "canary" subcommand attempts reboot(2). Never run this binary
// directly on a bare host — only inside a runsc-confined container. gVisor's
// sentry does not implement guest reboot(2) as a real host reboot regardless
// of seccomp (the guest never reaches the host kernel for it), but this
// binary does not verify it's sandboxed before trying, so treat "confined
// execution only" as an invariant of how it's invoked, not something it
// enforces itself.
package main

import (
	"bufio"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

// outcome is the single-line JSON result every subcommand prints to
// stdout. The calling ContainerRuntime backend parses this to build a
// runtime.Denial.
type outcome struct {
	OK        bool   `json:"ok"`
	Errno     int    `json:"errno,omitempty"`
	ErrnoName string `json:"errno_name,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func report(o outcome) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(o); err != nil {
		// Nothing left to report through if stdout itself is broken;
		// fail loudly on stderr and exit non-zero.
		fmt.Fprintf(os.Stderr, "probe: failed to write outcome: %v\n", err)
		os.Exit(2)
	}
}

func errnoOf(err error) (int, string, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno), errno.Error(), true
	}
	return 0, "", false
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe <canary|open|landlock-selftest|echo> [args...]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "canary":
		cmdCanary()
	case "open":
		cmdOpen(os.Args[2:])
	case "landlock-selftest":
		cmdLandlockSelftest(os.Args[2:])
	case "echo":
		cmdEcho()
	case "init":
		cmdInit(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "probe: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// cmdCanary attempts reboot(2). Every CompiledPolicy in this project
// deliberately omits it (compile.CanarySyscall) and compile refuses to
// compile a profile that allows it, so a confined container must always
// deny this. See runtime.runCanaryCheck, which is the actual consumer of
// this outcome in-process; this binary is what makes that check possible
// against a real runsc backend instead of a fake one.
func cmdCanary() {
	report(canaryOutcome())
}

// canaryOutcome attempts reboot(2) and reports what happened, without
// printing anything itself — shared by cmdCanary (direct invocation, for
// ad-hoc testing) and cmdInit (the real boot-time gate, see below).
func canaryOutcome() outcome {
	err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	if err == nil {
		// This is the failure case the whole canary exists to catch:
		// confinement was requested but is not actually active.
		return outcome{OK: true, Detail: "reboot(2) was NOT denied"}
	}
	errno, name, ok := errnoOf(err)
	if !ok {
		return outcome{OK: false, Detail: fmt.Sprintf("non-errno error: %v", err)}
	}
	return outcome{OK: false, Errno: errno, ErrnoName: name}
}

// cmdInit is the real container entrypoint runtime.go's runsc backend
// wraps every enforcing workload in (see BundleConfig.WrapWithCanaryShim).
// It runs the canary check itself, prints exactly one JSON outcome line to
// stdout, and only then — and only if the canary syscall was actually
// denied via seccomp with EPERM — execve()s into the real workload,
// replacing itself. A seccomp filter applied before a process starts
// survives execve, so the real workload inherits the exact confinement
// this check just observed; there is no gap between "we verified
// confinement" and "the real process started" for another process to run
// in.
//
// If the canary was NOT properly denied, cmdInit refuses to exec the real
// workload at all and exits non-zero instead. This is defense in depth
// for CLAUDE.md's "sandbox unavailable means calls are rejected, never
// run unconfined": even if the supervisor-level check in
// runtime.runCanaryCheck were somehow bypassed, this is a second,
// independent gate running inside the confined process itself.
//
// Usage: probe init -- <real-argv...>
func cmdInit(args []string) {
	sep := indexOf(args, "--")
	if sep < 0 || sep == len(args)-1 {
		fmt.Fprintln(os.Stderr, "usage: probe init -- <real-argv...>")
		os.Exit(2)
	}
	realArgs := args[sep+1:]

	o := canaryOutcome()
	report(o)

	const epermErrno = 1
	if o.OK || o.Errno != epermErrno {
		fmt.Fprintln(os.Stderr, "probe: canary syscall was not denied with EPERM — refusing to start the real workload unconfined")
		os.Exit(1)
	}

	// execve(2) takes a path, not a command name — it does no PATH
	// resolution. A workload declared as `node server.js` (the normal way
	// anyone writes it) would fail with ENOENT here, so resolve argv[0]
	// the way a shell would before handing off.
	binary, err := resolveExecutable(realArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: cannot resolve %q: %v\n", realArgs[0], err)
		os.Exit(1)
	}

	if err := unix.Exec(binary, realArgs, os.Environ()); err != nil {
		// execve reports ENOENT both for "the binary isn't there" and for
		// "the binary's ELF interpreter isn't there", and the second is by
		// far the more common confinement mistake — the loader is mapped
		// inside execve, so it never appears in a syscall trace and is
		// easy to leave out of a profile. Say which one it actually is.
		fmt.Fprintf(os.Stderr, "probe: exec %v (resolved to %s) failed: %v\n", realArgs, binary, err)
		fmt.Fprintf(os.Stderr, "probe: %s\n", diagnoseExecFailure(binary))
		os.Exit(1)
	}
}

// diagnoseExecFailure turns an opaque execve error into a statement about
// what is actually missing inside the sandbox.
func diagnoseExecFailure(binary string) string {
	if _, err := os.Stat(binary); err != nil {
		return fmt.Sprintf("%s is NOT present in the sandbox — the profile does not mount it", binary)
	}
	interp, err := readELFInterp(binary)
	if err != nil {
		return fmt.Sprintf("%s is present; could not read its ELF headers (%v)", binary, err)
	}
	if interp == "" {
		return fmt.Sprintf("%s is present and statically linked; exec failed for another reason", binary)
	}
	if _, err := os.Stat(interp); err != nil {
		return fmt.Sprintf("%s is present, but its ELF interpreter %s is NOT — add that path to the profile", binary, interp)
	}
	return fmt.Sprintf("%s and its interpreter %s are both present; exec failed for another reason", binary, interp)
}

// readELFInterp returns the PT_INTERP of an ELF binary, or "" if it is
// statically linked.
func readELFInterp(binary string) (string, error) {
	f, err := elf.Open(binary)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\x00"), nil
	}
	return "", nil
}

// resolveExecutable turns a command name into an absolute path, searching
// PATH when the name contains no slash. Inside the sandbox this only finds
// binaries whose paths the profile actually mounted — resolution can't
// reach anything confinement didn't already permit.
func resolveExecutable(name string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	return exec.LookPath(name)
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// cmdOpen attempts to open path for read ("r") or write ("w") and reports
// whether it succeeded. Used to verify that gVisor's mount configuration
// — the primary filesystem confinement mechanism per design note flag #2
// — actually keeps undeclared paths invisible to the guest.
func cmdOpen(args []string) {
	if len(args) != 2 || (args[1] != "r" && args[1] != "w") {
		fmt.Fprintln(os.Stderr, "usage: probe open <path> <r|w>")
		os.Exit(2)
	}
	path, mode := args[0], args[1]

	var err error
	switch mode {
	case "r":
		var f *os.File
		f, err = os.Open(path)
		if f != nil {
			f.Close()
		}
	case "w":
		var f *os.File
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
		if f != nil {
			f.Close()
		}
	}

	if err == nil {
		report(outcome{OK: true})
		return
	}
	errno, name, ok := errnoOf(err)
	if !ok {
		report(outcome{OK: false, Detail: err.Error()})
		return
	}
	report(outcome{OK: false, Errno: errno, ErrnoName: name})
}

// cmdLandlockSelftest self-applies a strict (non-best-effort) Landlock
// ruleset permitting only read access to allowPath, then attempts to open
// both allowPath (expect success) and denyPath (expect EACCES). Two
// outcome lines are printed, in that order. If the self-apply itself
// fails, a single outcome line with OK:false and Detail set is printed
// instead and nothing is attempted — a process that couldn't confine
// itself has nothing meaningful to report about what it can access.
//
// This directly tests design note flag #2: whether an LSM restriction
// self-applied by a process running inside a gVisor guest is enforced by
// the host kernel at all, or is a no-op because the sentry mediates the
// guest's file syscalls itself.
func cmdLandlockSelftest(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe landlock-selftest <allow-path> <deny-path>")
		os.Exit(2)
	}
	allowPath, denyPath := args[0], args[1]

	// Strict mode, not BestEffort: if this can't be fully applied on the
	// running kernel/environment, that failure IS the answer, and must
	// not be silently downgraded to "no restriction" — see design note §4
	// on why best-effort degradation is exactly the wrong default here.
	if err := landlock.V10.RestrictPaths(landlock.RODirs(allowPath)); err != nil {
		report(outcome{OK: false, Detail: fmt.Sprintf("landlock self-apply failed: %v", err)})
		return
	}

	cmdOpen([]string{allowPath, "r"})
	cmdOpen([]string{denyPath, "r"})
}

// cmdEcho reads one line from stdin and writes it back, prefixed, to
// stdout. It exists to exercise the stdio transport path (§4.1) end to
// end against a real confined process, independent of the syscall/path
// probes above.
func cmdEcho() {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		report(outcome{OK: false, Detail: "no input line"})
		return
	}
	fmt.Printf("echo: %s\n", scanner.Text())
}
