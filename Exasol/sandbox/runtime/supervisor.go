package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"mcp-warden/sandbox/compile"
)

// Mode identifies which supervisor produced a container. It is exposed
// only as a hardcoded return value on each concrete supervisor type (see
// EnforcingSupervisor.Mode), never as a settable struct field — so it is
// not representable to construct an enforcing-looking supervisor that
// reports itself as learning, or vice versa.
type Mode int

const (
	// ModeUnset must never appear on a value handed to a caller. Its only
	// purpose is to make the zero value of Mode visibly wrong if it ever
	// leaks out, instead of silently reading as one of the real modes.
	ModeUnset Mode = iota
	ModeEnforcing
	ModeLearning
)

func (m Mode) String() string {
	switch m {
	case ModeEnforcing:
		return "enforcing"
	case ModeLearning:
		return "learning"
	default:
		return "unset"
	}
}

// Container is one confined execution unit and its current lifecycle
// state. All mutation goes through transition(), so State never claims a
// step that didn't happen.
type Container struct {
	mu    sync.Mutex
	id    string
	state State
}

// ID returns the container's runtime identifier (used as the cgroup tag
// per §6.3).
func (c *Container) ID() string { return c.id }

// State returns the container's current lifecycle state.
func (c *Container) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Container) move(to State) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := transition(c.state, to); err != nil {
		return err
	}
	c.state = to
	return nil
}

func newContainerID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("runtime: generate container id: %w", err)
	}
	return "sbx_" + hex.EncodeToString(b), nil
}

// EnforcingSupervisor is the only supervisor type that ever produces a
// confined, verified container. Every code path in this type
// unconditionally applies seccomp + Landlock (via ContainerRuntime.Create)
// and unconditionally runs the canary self-test before a container reaches
// READY. There is no parameter or config value anywhere in this type that
// skips either step — that is deliberate, see design note §4.
type EnforcingSupervisor struct {
	rt ContainerRuntime
}

// NewEnforcingSupervisor constructs the enforcing supervisor. This is one
// of exactly two ways to get a Supervisor-shaped value in this codebase;
// the other is learning.New, in a separate package, which cannot produce
// an EnforcingSupervisor and vice versa.
func NewEnforcingSupervisor(rt ContainerRuntime) *EnforcingSupervisor {
	return &EnforcingSupervisor{rt: rt}
}

// Mode always reports ModeEnforcing. Hardcoded, not derived from state.
func (s *EnforcingSupervisor) Mode() Mode { return ModeEnforcing }

// NewContainer creates, confines, and verifies a container for policy.
// policy is expected to be the whole-session union produced by
// compile.Session — one container hosts a long-running server process
// serving every tool in the profile for the life of the session, and
// confinement is applied once, here, not per individual tool call (see
// compile.Session's doc for why). It only returns a container in
// StateReady; on any failure the container is left in (or moved to)
// StateRejected and a non-nil error is returned. Per CLAUDE.md, "sandbox
// unavailable means calls are rejected, never run unconfined" — callers
// must never treat an error here as license to run the tool call some
// other way.
func (s *EnforcingSupervisor) NewContainer(ctx context.Context, policy *compile.CompiledPolicy) (*Container, error) {
	id, err := newContainerID()
	if err != nil {
		return nil, err
	}
	c := &Container{id: id, state: StateInit}

	if err := c.move(StateProfileLoaded); err != nil {
		return nil, err
	}
	if err := c.move(StateConfining); err != nil {
		return nil, err
	}

	if err := s.rt.Create(ctx, c.id, policy); err != nil {
		_ = c.move(StateRejected)
		return nil, fmt.Errorf("runtime: confine container %s: %w", c.id, err)
	}

	if err := runCanaryCheck(ctx, s.rt, c.id); err != nil {
		_ = c.move(StateRejected)
		// Best-effort teardown of a container we just proved is not safe
		// to use. Its own failure doesn't change the outcome: this
		// container was never going to reach READY.
		_ = s.rt.Destroy(ctx, c.id)
		return nil, fmt.Errorf("runtime: container %s failed confinement verification: %w", c.id, err)
	}

	if err := c.move(StateReady); err != nil {
		return nil, err
	}
	return c, nil
}

// Execute runs one request against an already-verified container,
// enforcing the §6.3 serialization rule via the container's own state
// machine: a container not in StateReady (e.g. already EXECUTING) refuses
// a second concurrent call rather than silently interleaving it.
//
// A kernel denial observed in the result moves the container to
// StateQuarantined and returns a SandboxDenialError-shaped error; the
// container is never returned to READY after a denial. Quarantine here is
// instance-scoped only (§3.3/§5) — it says nothing about sibling
// containers or the artifact as a whole; that bookkeeping is IBAC/
// attestation territory (v1), out of scope for this package.
func (s *EnforcingSupervisor) Execute(ctx context.Context, c *Container, req ExecRequest) (ExecResult, error) {
	if err := c.move(StateExecuting); err != nil {
		return ExecResult{}, fmt.Errorf("runtime: container %s not available for execution: %w", c.id, err)
	}

	res, err := s.rt.Exec(ctx, c.id, req)
	if err != nil {
		// An execution transport error (not a kernel denial) still leaves
		// the container unusable until inspected; fail closed by
		// quarantining rather than guessing it's safe to reuse.
		_ = c.move(StateQuarantined)
		return ExecResult{}, fmt.Errorf("runtime: exec on container %s: %w", c.id, err)
	}

	if res.Denial.Occurred {
		_ = c.move(StateQuarantined)
		return res, fmt.Errorf("runtime: container %s quarantined: kernel denied %s %q (errno %d)",
			c.id, res.Denial.Kind, res.Denial.Detail, res.Denial.Errno)
	}

	if err := c.move(StateReady); err != nil {
		return res, err
	}
	return res, nil
}

// Destroy tears the container down from whatever non-terminal state it's
// in. Safe to call on a rejected or quarantined container.
func (s *EnforcingSupervisor) Destroy(ctx context.Context, c *Container) error {
	if err := c.move(StateDestroying); err != nil {
		return err
	}
	if err := s.rt.Destroy(ctx, c.id); err != nil {
		return fmt.Errorf("runtime: destroy container %s: %w", c.id, err)
	}
	return c.move(StateDestroyed)
}
