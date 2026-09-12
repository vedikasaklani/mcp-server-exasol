// Package runtime supervises confined container execution: the state
// machine in the sandbox design note §3, the quarantine transition on
// kernel denial, and the boot-time canary self-test that turns "we asked
// the kernel to confine this" into "we observed confinement working"
// (design note §4).
//
// This package owns the only code paths in the sandbox module that touch
// a real container runtime. Everything it depends on for policy content
// (sandbox/compile) is pure and already tested; everything it does with
// that policy — creating, probing, executing, destroying, quarantining —
// is exercised here against the ContainerRuntime interface, either a real
// backend (sandbox/runtime/runsc) or a fake for unit tests.
package runtime

import "fmt"

// State is one node in the container lifecycle state machine (design note
// §3). The zero value is StateInit.
type State int

const (
	StateInit State = iota
	StateProfileLoaded
	StateConfining
	StateReady
	StateExecuting
	StateQuarantined
	StateDestroying
	StateDestroyed
	StateRejected
)

func (s State) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateProfileLoaded:
		return "PROFILE_LOADED"
	case StateConfining:
		return "CONFINING"
	case StateReady:
		return "READY"
	case StateExecuting:
		return "EXECUTING"
	case StateQuarantined:
		return "QUARANTINED"
	case StateDestroying:
		return "DESTROYING"
	case StateDestroyed:
		return "DESTROYED"
	case StateRejected:
		return "REJECTED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// validTransitions is the adjacency map for the state machine. Any
// transition not listed here is illegal and transition() rejects it. This
// is the single source of truth for the lifecycle — in particular, there
// is no edge from REJECTED to any other state, and no edge from any state
// directly to EXECUTING except READY: a container can only run a tool call
// once its confinement has been verified (see canary.go), never as a
// shortcut from CONFINING.
var validTransitions = map[State]map[State]bool{
	StateInit:          {StateProfileLoaded: true},
	StateProfileLoaded: {StateConfining: true, StateRejected: true},
	StateConfining:     {StateReady: true, StateRejected: true, StateQuarantined: true},
	StateReady:         {StateExecuting: true, StateDestroying: true},
	StateExecuting:     {StateReady: true, StateQuarantined: true, StateDestroying: true},
	StateQuarantined:   {StateDestroying: true},
	StateRejected:      {StateDestroying: true}, // allow cleanup of a container that failed to confine
	StateDestroying:    {StateDestroyed: true},
	StateDestroyed:     {},
}

// transition moves from to iff the edge exists in validTransitions. It
// does not itself do any I/O — callers apply the corresponding kernel/
// runtime action before or after calling this, so a Container's state
// field never claims something the caller hasn't actually done.
func transition(from, to State) error {
	if validTransitions[from][to] {
		return nil
	}
	return fmt.Errorf("runtime: illegal state transition %s -> %s", from, to)
}
