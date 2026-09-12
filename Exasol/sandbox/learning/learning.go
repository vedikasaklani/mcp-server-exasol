// Package learning runs the capability-profiling driver (§3.2): the same
// sandbox, with seccomp in log-only mode and Landlock disabled, recording
// rather than denying (§6.4).
//
// A learning-mode execution is an unconfined execution. This package
// exists specifically so that fact can never be hidden behind a runtime
// mode flag: it does not import or share any code with
// sandbox/runtime.EnforcingSupervisor, it can only be constructed via an
// explicit, loudly-named acknowledgement, and it refuses to start if the
// environment looks like production. See the sandbox design note §4 for
// why "shared code with a mode switch" was rejected as the design here —
// that shape is exactly what turns one bad default into a silently
// unconfined production deployment.
package learning

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/runtime"
)

// productionEnvVar, when set to "production", causes New to refuse to
// start. Belt-and-suspenders alongside UnconfinedAcknowledgement: a
// deployment automation mistake that starts the learning binary in a
// production-labeled environment fails loudly instead of quietly running
// every tool call unconfined.
const productionEnvVar = "MCP_WARDEN_ENV"

// UnconfinedAcknowledgement proves the caller explicitly acknowledged that
// this package runs targets completely unconfined. It has no exported
// fields, so the only way to produce a value whose acknowledged bit is
// true is to call AcknowledgeUnconfinedExecution — a zero-value
// UnconfinedAcknowledgement{} (e.g. from a forgotten argument) is
// indistinguishable from "not acknowledged" and New rejects it.
type UnconfinedAcknowledgement struct{ acknowledged bool }

// AcknowledgeUnconfinedExecution is the only way to produce an
// acknowledgement that satisfies New. Its name is deliberately explicit:
// anyone reading a call site sees what they're opting into without having
// to chase a boolean flag back to its definition.
func AcknowledgeUnconfinedExecution() UnconfinedAcknowledgement {
	return UnconfinedAcknowledgement{acknowledged: true}
}

// Supervisor drives learning-mode containers. Every ExecutionRecord it
// produces reports LearningMode() as a hardcoded true — not a settable
// field — so it is not representable to emit a learning-mode record
// tagged as anything else.
type Supervisor struct {
	rt runtime.ContainerRuntime
}

// New constructs a learning Supervisor. It fails if ack was not obtained
// via AcknowledgeUnconfinedExecution, or if the environment is flagged as
// production via MCP_WARDEN_ENV.
func New(rt runtime.ContainerRuntime, ack UnconfinedAcknowledgement) (*Supervisor, error) {
	if !ack.acknowledged {
		return nil, fmt.Errorf("learning: refusing to start without an explicit UnconfinedAcknowledgement from AcknowledgeUnconfinedExecution — learning mode runs targets completely unconfined")
	}
	if v := os.Getenv(productionEnvVar); v == "production" {
		return nil, fmt.Errorf("learning: refusing to start: %s=production — learning mode must never run in a production environment", productionEnvVar)
	}
	return &Supervisor{rt: rt}, nil
}

// State is a learning-mode container's lifecycle. It is intentionally its
// own, smaller enum rather than a reuse of runtime.State: runtime.State's
// StateReady specifically means "confinement verified" (see
// runtime.runCanaryCheck), a claim that has no meaning here and must never
// be represented as true for a learning-mode container.
type State int

const (
	StateCreated State = iota
	StateRunning
	StateDestroyed
)

func (s State) String() string {
	switch s {
	case StateCreated:
		return "CREATED"
	case StateRunning:
		return "RUNNING"
	case StateDestroyed:
		return "DESTROYED"
	default:
		return "UNKNOWN"
	}
}

// Container is one unconfined profiling target.
type Container struct {
	mu    sync.Mutex
	id    string
	state State
}

func (c *Container) ID() string { return c.id }

func (c *Container) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func newContainerID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("learning: generate container id: %w", err)
	}
	return "learn_" + hex.EncodeToString(b), nil
}

// NewContainer starts an unconfined container for the given profile draft.
// policy is typically a permissive, in-progress CompiledPolicy — profiling
// runs to discover what a server actually does, not to enforce a
// predetermined allowlist — but this package places no requirement on its
// shape, since enforcement is off regardless of its content.
func (s *Supervisor) NewContainer(ctx context.Context, policy *compile.CompiledPolicy) (*Container, error) {
	id, err := newContainerID()
	if err != nil {
		return nil, err
	}
	if err := s.rt.CreateUnconfined(ctx, id, policy); err != nil {
		return nil, fmt.Errorf("learning: create unconfined container: %w", err)
	}
	return &Container{id: id, state: StateRunning}, nil
}

// ExecutionRecord is what a learning-mode invocation produces: observed
// behavior for §3.2's capability profiling, not an authorization decision.
// LearningMode always reports true — see the package doc for why that's a
// method, not a field.
type ExecutionRecord struct {
	RequestID     string
	ToolName      string
	SyscallsSeen  []string
	FilesTouched  []string
	NetworkDialed []string
	Timestamp     time.Time
}

// LearningMode always returns true. It cannot be constructed to return
// anything else.
func (ExecutionRecord) LearningMode() bool { return true }

// Execute drives one invocation against an unconfined container and
// returns what was observed, for the human review gate in §3.2 step 5 to
// approve, edit, or reject before it ever becomes an enforced profile.
// Unlike runtime.EnforcingSupervisor.Execute, there is no denial to react
// to — nothing is denied in learning mode — and no quarantine transition,
// because quarantine is a response to a kernel enforcing a boundary that,
// here, does not exist.
func (s *Supervisor) Execute(ctx context.Context, c *Container, req runtime.ExecRequest) (ExecutionRecord, error) {
	res, err := s.rt.Exec(ctx, c.ID(), req)
	if err != nil {
		return ExecutionRecord{}, fmt.Errorf("learning: exec on container %s: %w", c.ID(), err)
	}
	_ = res // v0: payload/observation extraction lands with the profiling driver, not this package.
	return ExecutionRecord{
		RequestID: req.RequestID,
		ToolName:  req.ToolName,
		Timestamp: time.Now(),
	}, nil
}

// Destroy tears the container down. Like runtime.EnforcingSupervisor,
// nothing persists past this call.
func (s *Supervisor) Destroy(ctx context.Context, c *Container) error {
	c.mu.Lock()
	c.state = StateDestroyed
	c.mu.Unlock()
	return s.rt.Destroy(ctx, c.ID())
}
