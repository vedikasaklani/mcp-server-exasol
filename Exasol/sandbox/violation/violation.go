// Package violation correlates kernel-level denial events back to the
// request that caused them, and shapes that correlation into an error the
// proxy gateway can turn into a diagnosable response.
//
// It is deliberately effect-agnostic about where events come from: §6.3
// establishes cgroup ID as the correlation key now, on the assumption that
// Tetragon (v2) will emit events keyed the same way. Building this now,
// even though nothing but seccomp/Landlock denials feed it in v0, means
// v2 doesn't need to rework the correlation path — only add a producer.
package violation

import (
	"fmt"
	"sync"
	"time"
)

// DenialKind mirrors runtime.DenialKind. Duplicated here rather than
// imported so this package has no dependency on sandbox/runtime — it only
// needs to know about denial shapes, not how containers are supervised.
type DenialKind string

const (
	DenialKindSeccomp  DenialKind = "seccomp"
	DenialKindLandlock DenialKind = "landlock"
)

// Event is one kernel-level denial, as diagnosable as the kernel lets it
// be. Seccomp denials surface as EPERM with a syscall identity; Landlock
// denials surface as EACCES with a path but, on kernels before Landlock's
// audit integration landed, no kernel-native record of which rule matched
// — see design note flag on Landlock diagnosability. Detail is best-effort
// in that case, populated from whatever the caller could infer at
// apply-time, not guaranteed complete.
type Event struct {
	Kind      DenialKind
	Syscall   string // set for DenialKindSeccomp
	Path      string // set for DenialKindLandlock
	Errno     int
	CgroupID  string
	Timestamp time.Time
}

// DenialError is what a Supervisor returns to its caller when a kernel
// denial occurs, carrying enough context (§6.5 / design note §5) for the
// proxy gateway to produce a diagnosable MCP error response rather than a
// bare "the tool call failed."
type DenialError struct {
	RequestID string
	Event     Event
}

func (e *DenialError) Error() string {
	switch e.Event.Kind {
	case DenialKindSeccomp:
		return fmt.Sprintf("sandbox: request %s denied: seccomp blocked syscall %q (errno %d)", e.RequestID, e.Event.Syscall, e.Event.Errno)
	case DenialKindLandlock:
		return fmt.Sprintf("sandbox: request %s denied: landlock blocked access to %q (errno %d)", e.RequestID, e.Event.Path, e.Event.Errno)
	default:
		return fmt.Sprintf("sandbox: request %s denied: unknown denial kind %q (errno %d)", e.RequestID, e.Event.Kind, e.Event.Errno)
	}
}

// CorrelationStore maps cgroup IDs to request IDs so a kernel event that
// only carries a cgroup ID can be attributed back to the MCP tool call
// that produced it (§6.3). Stamp before invoking a tool call; Clear once
// the container returns to an idle/ready state so a stale mapping can
// never attribute a later, unrelated event to an old request.
type CorrelationStore struct {
	mu       sync.RWMutex
	byCgroup map[string]string
}

// NewCorrelationStore returns an empty store.
func NewCorrelationStore() *CorrelationStore {
	return &CorrelationStore{byCgroup: make(map[string]string)}
}

// Stamp records that cgroupID is currently executing requestID.
func (s *CorrelationStore) Stamp(cgroupID, requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byCgroup[cgroupID] = requestID
}

// Lookup returns the request ID currently attributed to cgroupID, if any.
func (s *CorrelationStore) Lookup(cgroupID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byCgroup[cgroupID]
	return id, ok
}

// Clear removes cgroupID's mapping. Call this once a request completes —
// within a session, syscall attribution is exact only while the mapping
// is live (design note §5 / architecture §6.3).
func (s *CorrelationStore) Clear(cgroupID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byCgroup, cgroupID)
}
