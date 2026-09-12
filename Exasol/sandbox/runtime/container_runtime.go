package runtime

import (
	"context"
	"time"

	"mcp-warden/sandbox/compile"
)

// ContainerRuntime is the seam between this package's lifecycle/quarantine
// logic and an actual container backend (real: sandbox/runtime/runsc;
// fake: sandbox/runtime/runtimetest, used by this package's own tests).
//
// Create and CreateUnconfined are deliberately two separate methods rather
// than one method with a "confined bool" parameter — see design note §4.
// An implementation that collapsed them into a shared branch would
// reintroduce exactly the misconfiguration risk that split is meant to
// prevent, so callers should treat the existence of two methods, not a
// flag, as the contract.
type ContainerRuntime interface {
	// Create starts a container with full confinement applied before the
	// entrypoint can run: seccomp default-deny (EPERM), Landlock ruleset,
	// no network interfaces. This is the only path EnforcingSupervisor
	// ever takes.
	Create(ctx context.Context, id string, policy *compile.CompiledPolicy) error

	// CreateUnconfined starts a container with seccomp in log-only mode
	// and Landlock disabled (§6.4). Only sandbox/learning may call this;
	// every execution against a container created this way is, by
	// construction, unconfined and must be flagged as such.
	CreateUnconfined(ctx context.Context, id string, policy *compile.CompiledPolicy) error

	// ProbeSyscall invokes a single named syscall inside the container and
	// reports whether the kernel denied it. Used by the canary self-test
	// (canary.go) to verify confinement is actually active, and could be
	// reused by learning mode to record what a profiling run touches.
	ProbeSyscall(ctx context.Context, id string, syscallName string) (Denial, error)

	// Exec runs the confined entrypoint for one request. Per §6.3, callers
	// serialize this: one in-flight call per container.
	Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error)

	// Destroy tears the container down. No state persists past this call.
	Destroy(ctx context.Context, id string) error
}

// Denial is what ProbeSyscall or Exec observed the kernel do in response
// to a disallowed operation.
type Denial struct {
	Occurred bool
	Kind     DenialKind
	Detail   string // syscall name for seccomp, path for Landlock
	Errno    int
}

// DenialKind distinguishes which enforcement layer produced a Denial.
type DenialKind string

const (
	DenialKindSeccomp  DenialKind = "seccomp"
	DenialKindLandlock DenialKind = "landlock"
	DenialKindNone     DenialKind = ""
)

// ExecRequest is one tool invocation to run inside an already-confined,
// already-verified container.
type ExecRequest struct {
	RequestID string
	ToolName  string
	Payload   []byte
	Timeout   time.Duration
	// Notify marks a JSON-RPC notification: a message with no id, which
	// the protocol says gets no response. Waiting for one would block
	// until the request timeout and then report a failure that never
	// happened — and MCP's own handshake requires sending exactly such a
	// message (notifications/initialized) before a server will serve
	// tools, so this is not an edge case.
	Notify bool
}

// ExecResult is the outcome of one ExecRequest. Denial is the zero value
// (Occurred: false) on a clean execution; Supervisor.Execute inspects it
// to decide whether the container returns to READY or moves to
// QUARANTINED.
type ExecResult struct {
	Status  string
	Payload []byte
	Denial  Denial
	// Unsolicited holds messages the server emitted while this request was
	// in flight that were not its response — JSON-RPC notifications
	// (progress, logging, list-changed) that a real MCP server interleaves
	// with responses. They're surfaced rather than dropped because the
	// response guard (§4.4) will need to inspect them too: content
	// reaching the client is content reaching the model, whether or not it
	// answered a request.
	Unsolicited [][]byte
}
