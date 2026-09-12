package runsc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/runtime"
)

const (
	// handshakeTimeout bounds how long Create waits for the canary shim's
	// single stdout line before giving up and failing closed. The shim's
	// own work (one syscall attempt, one JSON encode) is sub-millisecond;
	// this budget is almost entirely runsc's container start latency, set
	// generously so host load causes a slow start rather than a spurious
	// "confinement not verified" rejection.
	handshakeTimeout = 15 * time.Second

	// destroyGraceTimeout bounds each teardown step. Teardown is
	// best-effort by nature — a container being destroyed does not get to
	// block the caller forever by refusing to die.
	destroyGraceTimeout = 5 * time.Second

	// lineBufferSize is how many output lines a container may run ahead of
	// its reader before the reader goroutine blocks. Bounded on purpose:
	// an unbounded buffer lets a chatty (or hostile) server drive host
	// memory growth from inside the sandbox.
	lineBufferSize = 256
)

// syncBuffer is a mutex-guarded bytes.Buffer. os/exec writes a command's
// stderr from its own goroutine, so anything reading that buffer while the
// process is alive needs synchronization — a plain bytes.Buffer here is a
// data race, not a theoretical one.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Runtime is the real, gVisor-backed implementation of
// runtime.ContainerRuntime. One Runtime instance serves one MCP server
// image: Rootfs.Args is that server's entrypoint, shared by every
// container this Runtime creates. A deployment running multiple attested
// server images uses one Runtime per image.
type Runtime struct {
	// RunscPath is the runsc binary to invoke. Empty means "runsc" via
	// PATH lookup.
	RunscPath string
	// BundleRoot is the host directory under which per-container OCI
	// bundles are written. Created if it doesn't exist.
	BundleRoot string
	// Rootfs describes the server image this Runtime confines: where its
	// root filesystem lives on disk and its entrypoint argv/env/cwd.
	// Per-session filesystem and network restrictions come from the
	// CompiledPolicy passed to Create, layered on top via Mounts.
	Rootfs BundleConfig
	// ProbeBinaryPath is the host path to the built probe binary
	// (sandbox/runtime/runsc/probe). Required: Create's canary shim
	// depends on it.
	ProbeBinaryPath string
	// Limits are the cgroup v2 resource caps applied to every container
	// (§6.1.5). The zero value means DefaultLimits().
	Limits Limits

	// Trace turns on gVisor's own strace output for every container this
	// Runtime creates, written as JSON into the container's bundle
	// directory and consumed live by sandbox/analyze.
	//
	// This is observation layered on top of enforcement, never instead of
	// it: seccomp, the mount topology, and the network namespace are
	// applied identically whether Trace is set or not. What it buys is
	// the ability to say what a server did, not merely that it was
	// stopped from doing something. What it costs is real — the sentry
	// formats and writes a log line per syscall — which is why
	// TraceSyscalls exists and why the flag is opt-in.
	Trace bool
	// TraceSyscalls limits tracing to named syscalls. Empty traces
	// everything, which is complete and expensive; DetectionSyscalls is
	// the curated set the built-in detectors actually read.
	TraceSyscalls []string
	// GlobalFlags are runsc flags placed before the subcommand, for
	// invocation-level concerns the policy has no opinion about — chiefly
	// `--rootless --ignore-cgroups`, which let the sandbox run without
	// root.
	//
	// What that mode keeps is the important part: seccomp still enforces
	// the compiled filter and the mount topology still hides every
	// undeclared path (both verified by the canary, which is denied with
	// EPERM exactly as it is under root). What it gives up is §6.1.5's
	// cgroup limits — a server can then exhaust host CPU or memory — so a
	// caller setting this must say so rather than let it pass for the
	// fully confined configuration.
	GlobalFlags []string

	// TraceRoot is the host directory under which per-container trace
	// logs are written. Defaults to a sibling of BundleRoot.
	//
	// Deliberately NOT inside the bundle. An OCI bundle is config.json
	// plus a rootfs; runsc's gofer and sentry each take their own view of
	// that directory, and putting a log the host must keep appending to
	// inside it makes the log's visibility depend on which process opens
	// it and when. Keeping it outside removes the question.
	TraceRoot string

	mu         sync.Mutex
	containers map[string]*managedContainer
	// traceFilterOff records that the syscall filter had to be dropped
	// because this runsc rejected it. Sticky: once proven unusable there
	// is no reason to pay a failed container start to re-prove it.
	traceFilterOff atomic.Bool
	// traceOff records that tracing had to be abandoned entirely.
	traceOff atomic.Bool
}

// TraceDegraded reports whether tracing had to be weakened or dropped to
// get containers started, and why. The daemon surfaces this rather than
// letting analysis quietly cover less than the operator asked for.
func (r *Runtime) TraceDegraded() (filterDropped, tracingDropped bool) {
	return r.traceFilterOff.Load(), r.traceOff.Load()
}

// DetectionSyscalls is the syscall set the built-in detectors consume.
// Tracing only these keeps the sentry's logging cost proportional to the
// interesting fraction of a workload's syscalls rather than to all of
// them — a server's hot loop is futex, epoll_wait and clock_gettime, none
// of which any detector reads.
//
// Membership is derived from what sandbox/analyze's applyLocked
// switches on. Adding a detector that needs a new syscall means adding it
// here too, or the detector silently sees nothing.
//
// The list is deliberately conservative about newer syscalls
// (openat2, clone3, statx, faccessat2, recvmmsg, ...). gVisor builds its
// strace filter from its own syscall table, and a name it does not
// implement is a fatal error at sandbox boot, not a warning — which
// presents as "cannot read client sync file: EOF" with no further
// explanation. Omitting a syscall costs one detector some visibility;
// including an unknown one costs the container its ability to start.
// startContainer's fallback covers the case anyway (see traceArgs).
var DetectionSyscalls = []string{
	// descriptor lifecycle — the fd table that makes byte-flow
	// attribution possible
	"socket", "socketpair", "accept", "accept4", "connect", "bind", "close",
	"dup", "dup2", "dup3",
	// path access
	"open", "openat", "creat",
	"stat", "lstat", "newfstatat", "access", "faccessat",
	"readlink", "readlinkat", "getdents64",
	"unlink", "unlinkat", "rename", "renameat", "renameat2",
	"mkdir", "mkdirat", "rmdir", "chmod", "fchmodat", "truncate",
	"link", "linkat", "symlink", "symlinkat",
	// data movement
	"read", "pread64", "readv", "preadv", "recvfrom", "recvmsg",
	"write", "pwrite64", "writev", "pwritev", "sendto", "sendmsg",
	// process and code loading
	"execve", "execveat", "clone", "fork", "vfork",
	"ptrace", "process_vm_readv", "process_vm_writev",
	"mount", "umount2", "pivot_root", "setns", "unshare",
	"reboot",
}

// TraceDir returns the directory this Runtime writes container id's trace
// log into, and whether tracing is on at all.
func (r *Runtime) TraceDir(id string) (string, bool) {
	if !r.Trace || r.traceOff.Load() {
		// Reporting "no trace directory" rather than an empty one is what
		// makes the analyzer report itself as blind instead of reporting
		// a clean session it never observed.
		return "", false
	}
	return filepath.Join(r.traceRoot(), id), true
}

// bootLogTail returns the error-level lines from runsc's own debug log
// for this container, formatted for inclusion in an error.
//
// Without this, a sandbox that dies during boot reports only "cannot read
// client sync file: ... EOF" — the parent noticing that the child is
// gone, carrying none of the reason. The reason is in the sentry's debug
// log, which this Runtime already asks runsc to write. Not reading it
// would be the same mistake §6.1.2 warns about for seccomp: choosing a
// failure mode that discards the context making the failure diagnosable.
func (r *Runtime) bootLogTail(id string) string {
	dir, ok := r.TraceDir(id)
	if !ok {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var lines []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, raw := range strings.Split(string(b), "\n") {
			if !strings.Contains(raw, `"level":"error"`) && !strings.Contains(raw, "Error ") &&
				!strings.Contains(raw, "panic") && !strings.Contains(raw, "FATAL") {
				continue
			}
			var ll struct {
				Msg string `json:"msg"`
			}
			if json.Unmarshal([]byte(raw), &ll) == nil && ll.Msg != "" {
				lines = append(lines, ll.Msg)
			} else {
				lines = append(lines, raw)
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return "\n  runsc boot log:\n    " + strings.Join(lines, "\n    ")
}

func (r *Runtime) traceRoot() string {
	if r.TraceRoot != "" {
		return r.TraceRoot
	}
	return r.BundleRoot + "-trace"
}

// outputLine is one line read from a container's stdout, or the terminal
// error that ended the stream.
type outputLine struct {
	text string
	err  error
}

type managedContainer struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	lines     <-chan outputLine
	stderr    *syncBuffer
	bundleDir string

	// closed is closed by Destroy to release the reader goroutine even if
	// nothing is draining lines.
	closed chan struct{}
	// waitDone is closed once cmd.Wait() has returned, so Destroy can
	// bound its wait instead of blocking forever on a process that won't
	// die.
	waitDone chan struct{}

	// canaryResult is captured once, from the shim's handshake line at
	// Create time (enforcing containers only). There is no valid way to
	// re-probe an arbitrary already-running third-party binary for an
	// arbitrary syscall's confinement after that point — see ProbeSyscall.
	canaryResult runtime.Denial
	hasCanary    bool
}

func (r *Runtime) runscBinary() string {
	if r.RunscPath != "" {
		return r.RunscPath
	}
	return "runsc"
}

// runscCmd builds a runsc invocation with the global flags applied.
//
// Every subcommand must carry them, not just `run`: --rootless changes
// which state directory gVisor keeps container metadata in, so a `delete`
// issued without it looks for a container that, as far as it can see,
// does not exist — and the container it failed to find keeps running.
func (r *Runtime) runscCmd(args ...string) *exec.Cmd {
	full := append(append([]string{}, r.GlobalFlags...), args...)
	return exec.Command(r.runscBinary(), full...)
}

func (r *Runtime) bundleDir(id string) string {
	return filepath.Join(r.BundleRoot, id)
}

func (r *Runtime) limits() Limits {
	if r.Limits == (Limits{}) {
		return DefaultLimits()
	}
	return r.Limits
}

// Create starts an enforcing container: full compiled seccomp policy,
// declared-path-only mounts, cgroup limits, and the canary shim wrapping
// the real entrypoint so nothing of the workload runs unless the canary
// syscall was actually denied. See design note §4 and probe/main.go's
// cmdInit.
func (r *Runtime) Create(ctx context.Context, id string, policy *compile.CompiledPolicy) error {
	if r.ProbeBinaryPath == "" {
		return fmt.Errorf("runsc: ProbeBinaryPath is required to create an enforcing container")
	}
	spec, err := GenerateSpec(policy, BundleConfig{
		RootfsPath:         r.Rootfs.RootfsPath,
		Args:               r.Rootfs.Args,
		Env:                r.Rootfs.Env,
		Cwd:                r.Rootfs.Cwd,
		ProbeBinaryPath:    r.ProbeBinaryPath,
		WrapWithCanaryShim: true,
		Limits:             r.limits(),
	})
	if err != nil {
		return fmt.Errorf("runsc: generate spec: %w", err)
	}
	return r.startContainerWithFallback(ctx, id, spec, true)
}

// CreateUnconfined starts a learning-mode container: log-only seccomp, no
// mount restriction, no canary shim. Only sandbox/learning should ever
// call this — see that package's doc comment.
func (r *Runtime) CreateUnconfined(ctx context.Context, id string, policy *compile.CompiledPolicy) error {
	spec, err := GenerateUnconfinedSpec(BundleConfig{
		RootfsPath:      r.Rootfs.RootfsPath,
		Args:            r.Rootfs.Args,
		Env:             r.Rootfs.Env,
		Cwd:             r.Rootfs.Cwd,
		ProbeBinaryPath: r.ProbeBinaryPath,
		Limits:          r.limits(),
	})
	if err != nil {
		return fmt.Errorf("runsc: generate unconfined spec: %w", err)
	}
	return r.startContainerWithFallback(ctx, id, spec, false)
}

// traceArgs builds the top-level runsc flags that turn on tracing. They
// go before the subcommand because they configure the runsc process
// itself, not the `run` operation.
func (r *Runtime) traceArgs(id string) []string {
	traceDir, ok := r.TraceDir(id)
	if !ok || r.traceOff.Load() {
		return nil
	}
	if err := os.MkdirAll(traceDir, 0o755); err != nil {
		// Nowhere to write the trace. Confinement is unaffected, so this
		// degrades analysis rather than failing the container.
		r.traceOff.Store(true)
		return nil
	}
	args := []string{
		"-strace",
		"-debug",
		"-debug-log=" + traceDir + string(os.PathSeparator),
		"-debug-log-format=json",
	}
	if len(r.TraceSyscalls) > 0 && !r.traceFilterOff.Load() {
		args = append(args, "-strace-syscalls="+strings.Join(r.TraceSyscalls, ","))
	}
	return args
}

// startContainerWithFallback starts a container and, if tracing is the
// reason it would not start, weakens tracing and retries.
//
// The ordering encodes what is negotiable. Confinement never is: a
// failure to apply seccomp or the mount topology is returned untouched
// and the container is rejected. Observation is: a syscall filter this
// runsc will not accept costs visibility, and running confined but less
// observable beats not running at all — provided the degradation is
// recorded and surfaced, which TraceDegraded does.
func (r *Runtime) startContainerWithFallback(ctx context.Context, id string, spec *specs.Spec, expectHandshake bool) error {
	err := r.startContainer(ctx, id, spec, expectHandshake)
	if err == nil || !r.Trace {
		return err
	}

	if len(r.TraceSyscalls) > 0 && !r.traceFilterOff.Load() {
		r.traceFilterOff.Store(true)
		r.cleanupFailed(id)
		if retryErr := r.startContainer(ctx, id, spec, expectHandshake); retryErr == nil {
			return nil
		}
	}
	if !r.traceOff.Load() {
		r.traceOff.Store(true)
		r.cleanupFailed(id)
		if retryErr := r.startContainer(ctx, id, spec, expectHandshake); retryErr == nil {
			return nil
		}
	}
	// Tracing was not the problem. Report the original failure, which is
	// the one that describes the actual fault.
	return err
}

// cleanupFailed clears the debris of a container that did not start, so a
// retry is not refused for reusing an id runsc still half-remembers.
func (r *Runtime) cleanupFailed(id string) {
	r.mu.Lock()
	mc, ok := r.containers[id]
	delete(r.containers, id)
	r.mu.Unlock()
	if ok {
		r.forceTeardown(id, mc)
		return
	}
	_ = r.runscCmd("delete", "--force", id).Run()
	_ = os.RemoveAll(r.bundleDir(id))
	r.removeTrace(id)
}

func (r *Runtime) startContainer(ctx context.Context, id string, spec *specs.Spec, expectHandshake bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	dir := r.bundleDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("runsc: create bundle dir: %w", err)
	}
	cfgBytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("runsc: marshal config.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfgBytes, 0o644); err != nil {
		return fmt.Errorf("runsc: write config.json: %w", err)
	}

	runArgs := append(append(append([]string{}, r.GlobalFlags...), r.traceArgs(id)...), "run", "--bundle", dir, id)

	// Not CommandContext: the container must outlive the (short-lived)
	// Create context. Its lifetime is owned explicitly by Destroy.
	cmd := exec.Command(r.runscBinary(), runArgs...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("runsc: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("runsc: stdout pipe: %w", err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("runsc: start: %w%s", err, r.bootLogTail(id))
	}

	mc := &managedContainer{
		cmd:       cmd,
		stdin:     stdin,
		stderr:    stderr,
		bundleDir: dir,
		closed:    make(chan struct{}),
		waitDone:  make(chan struct{}),
	}
	mc.lines = startReader(stdout, mc.closed)

	go func() {
		_ = cmd.Wait()
		close(mc.waitDone)
	}()

	if expectHandshake {
		denial, err := readCanaryHandshake(mc, handshakeTimeout)
		if err != nil {
			r.forceTeardown(id, mc)
			return fmt.Errorf("runsc: canary handshake with container %s: %w (stderr: %s)%s", id, err, mc.stderr.String(), r.bootLogTail(id))
		}
		mc.canaryResult = denial
		mc.hasCanary = true
	}

	r.mu.Lock()
	if r.containers == nil {
		r.containers = make(map[string]*managedContainer)
	}
	r.containers[id] = mc
	r.mu.Unlock()

	return nil
}

// startReader owns the container's stdout for the container's whole
// lifetime. Exactly one goroutine ever reads the pipe, which is what makes
// request/response pairing safe: a timed-out read leaves its line in the
// channel to be handled deliberately, instead of leaving an orphaned
// reader behind to steal a later response (and to race the next reader on
// the same bufio.Reader).
func startReader(stdout io.Reader, closed <-chan struct{}) <-chan outputLine {
	lines := make(chan outputLine, lineBufferSize)
	go func() {
		defer close(lines)
		rd := bufio.NewReader(stdout)
		for {
			text, err := rd.ReadString('\n')
			if text != "" {
				select {
				case lines <- outputLine{text: text}:
				case <-closed:
					return
				}
			}
			if err != nil {
				select {
				case lines <- outputLine{err: err}:
				case <-closed:
				}
				return
			}
		}
	}()
	return lines
}

// readCanaryHandshake reads the shim's single JSON outcome line — printed
// before it execs into the real workload (or exits, if the canary wasn't
// denied) — and converts it into a runtime.Denial. A timeout here is a
// Create failure, never a fallback to treating the container as
// confined-by-assumption (CLAUDE.md's fail-closed requirement).
func readCanaryHandshake(mc *managedContainer, timeout time.Duration) (runtime.Denial, error) {
	select {
	case line, ok := <-mc.lines:
		if !ok {
			return runtime.Denial{}, fmt.Errorf("container exited before writing a canary handshake")
		}
		if line.err != nil && line.text == "" {
			return runtime.Denial{}, fmt.Errorf("read handshake line: %w", line.err)
		}
		var o probeOutcome
		if err := json.Unmarshal([]byte(line.text), &o); err != nil {
			return runtime.Denial{}, fmt.Errorf("parse handshake line %q: %w", line.text, err)
		}
		return o.toDenial(), nil
	case <-time.After(timeout):
		return runtime.Denial{}, fmt.Errorf("timed out after %s waiting for canary handshake", timeout)
	}
}

// probeOutcome mirrors probe/main.go's outcome struct. Duplicated rather
// than shared via import: probe is a `package main` binary, not a library.
type probeOutcome struct {
	OK        bool   `json:"ok"`
	Errno     int    `json:"errno,omitempty"`
	ErrnoName string `json:"errno_name,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

func (o probeOutcome) toDenial() runtime.Denial {
	if o.OK {
		return runtime.Denial{Occurred: false}
	}
	return runtime.Denial{
		Occurred: true,
		Kind:     runtime.DenialKindSeccomp,
		Detail:   compile.CanarySyscall,
		Errno:    o.Errno,
	}
}

// ProbeSyscall only supports compile.CanarySyscall, returning the result
// captured during Create's handshake. There is no general mechanism here
// to probe an arbitrary syscall against an already-running, arbitrary
// third-party server process after startup — that would need either a
// cooperating in-process shim (which a real server doesn't have) or
// kernel-level event correlation (Tetragon, v2). The boot-time canary is
// the one check v0 can make with confidence.
func (r *Runtime) ProbeSyscall(ctx context.Context, id string, syscallName string) (runtime.Denial, error) {
	if syscallName != compile.CanarySyscall {
		return runtime.Denial{}, fmt.Errorf("runsc: ProbeSyscall only supports the canary syscall in v0, got %q", syscallName)
	}
	r.mu.Lock()
	mc, ok := r.containers[id]
	r.mu.Unlock()
	if !ok {
		return runtime.Denial{}, fmt.Errorf("runsc: unknown container %s", id)
	}
	if !mc.hasCanary {
		return runtime.Denial{}, fmt.Errorf("runsc: container %s has no captured canary result (unconfined container?)", id)
	}
	return mc.canaryResult, nil
}

// jsonRPCID extracts the "id" field of a JSON-RPC message, if it has one.
// Notifications legitimately have no id, which is exactly why Exec can't
// assume one-line-in/one-line-out.
func jsonRPCID(payload []byte) (string, bool) {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return "", false
	}
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		return "", false
	}
	return string(msg.ID), true
}

// Exec relays one request to the container's already-running process over
// the same stdio pipes Create wired up — matching §4.1's "the proxy...
// spawns the real server as a child, owning both pipes," with runsc's
// confinement underneath that same child process.
//
// If the request is a JSON-RPC call with an id, Exec reads until it sees a
// response carrying that id, skipping anything else the server emits in
// the meantime. Real MCP servers send unsolicited notifications (progress,
// logging, list-changed) interleaved with responses, so treating the next
// line as "the answer" mispairs requests under exactly the conditions
// production hits and tests usually don't.
//
// Denial detection here is necessarily limited: v0 has no kernel-level
// event correlation (that's Tetragon, v2 — architecture §6.1.6). A
// mid-session seccomp denial (SCMP_ACT_ERRNO) doesn't kill the process or
// notify us; it returns EPERM to whatever syscall the server attempted,
// and whether that becomes visible depends on the server's own error
// handling. What this CAN detect is the process dying or the pipe
// breaking, which EnforcingSupervisor.Execute already treats as reason
// enough to quarantine — so a transport failure surfaces as a plain error
// rather than a fabricated Denial.
func (r *Runtime) Exec(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
	r.mu.Lock()
	mc, ok := r.containers[id]
	r.mu.Unlock()
	if !ok {
		return runtime.ExecResult{}, fmt.Errorf("runsc: unknown container %s", id)
	}

	payload := bytes.TrimRight(req.Payload, "\n")
	if _, err := mc.stdin.Write(append(payload, '\n')); err != nil {
		return runtime.ExecResult{}, fmt.Errorf("runsc: write request to container %s: %w (stderr: %s)", id, err, mc.stderr.String())
	}

	if req.Notify {
		// A notification has no response by definition. Returning here
		// is the protocol being followed, not a shortcut.
		return runtime.ExecResult{Status: "SENT"}, nil
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.After(timeout)
	wantID, matchByID := jsonRPCID(payload)

	var skipped [][]byte
	for {
		select {
		case line, ok := <-mc.lines:
			if !ok {
				return runtime.ExecResult{}, fmt.Errorf("runsc: container %s closed its output stream (stderr: %s)", id, mc.stderr.String())
			}
			if line.err != nil && line.text == "" {
				return runtime.ExecResult{}, fmt.Errorf("runsc: read response from container %s: %w (stderr: %s)", id, line.err, mc.stderr.String())
			}
			text := bytes.TrimRight([]byte(line.text), "\n")
			if matchByID {
				if gotID, ok := jsonRPCID(text); !ok || gotID != wantID {
					skipped = append(skipped, text)
					continue
				}
			}
			return runtime.ExecResult{
				Status:      "SUCCESS",
				Payload:     text,
				Unsolicited: skipped,
			}, nil
		case <-deadline:
			return runtime.ExecResult{}, fmt.Errorf("runsc: request %s to container %s timed out after %s", req.RequestID, id, timeout)
		case <-ctx.Done():
			return runtime.ExecResult{}, ctx.Err()
		}
	}
}

// forceTeardown kills and cleans up a container that never made it into
// the live set (e.g. a failed canary handshake). Every step is
// best-effort: this path runs because something already went wrong.
func (r *Runtime) forceTeardown(id string, mc *managedContainer) {
	close(mc.closed)
	_ = mc.stdin.Close()
	if mc.cmd.Process != nil {
		_ = mc.cmd.Process.Kill()
	}
	select {
	case <-mc.waitDone:
	case <-time.After(destroyGraceTimeout):
	}
	_ = r.runscCmd("delete", "--force", id).Run()
	_ = os.RemoveAll(mc.bundleDir)
	r.removeTrace(id)
}

// removeTrace deletes a destroyed container's trace log. Callers stop
// tailing before destroying (see pool.retire), so nothing is reading it
// by this point, and a daemon that kept every retired container's trace
// would grow on disk without bound.
func (r *Runtime) removeTrace(id string) {
	// Not via TraceDir: that reports nothing once tracing has been turned
	// off, and a directory written before it was turned off still needs
	// removing.
	if r.BundleRoot == "" && r.TraceRoot == "" {
		return
	}
	_ = os.RemoveAll(filepath.Join(r.traceRoot(), id))
}

// Destroy tears the container down: stdin EOF to invite a graceful exit,
// escalating to SIGTERM then SIGKILL, then runsc delete and bundle
// cleanup. Every wait is bounded — a container that refuses to die does
// not get to block the caller indefinitely.
func (r *Runtime) Destroy(ctx context.Context, id string) error {
	r.mu.Lock()
	mc, ok := r.containers[id]
	delete(r.containers, id)
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("runsc: unknown container %s", id)
	}

	close(mc.closed)
	_ = mc.stdin.Close()
	_ = r.runscCmd("kill", id, "TERM").Run()

	select {
	case <-mc.waitDone:
	case <-time.After(destroyGraceTimeout):
		_ = r.runscCmd("kill", id, "KILL").Run()
		if mc.cmd.Process != nil {
			_ = mc.cmd.Process.Kill()
		}
		select {
		case <-mc.waitDone:
		case <-time.After(destroyGraceTimeout):
			// Give up waiting; fall through to delete/cleanup so a stuck
			// sandbox process can't wedge the caller forever.
		}
	}

	_ = r.runscCmd("delete", "--force", id).Run()
	r.removeTrace(id)
	_ = os.RemoveAll(mc.bundleDir)
	return nil
}

var _ runtime.ContainerRuntime = (*Runtime)(nil)
