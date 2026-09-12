// Package runtimetest provides an in-memory fake of runtime.ContainerRuntime
// for unit tests, so the lifecycle/quarantine/canary logic in
// sandbox/runtime and sandbox/learning can be exercised without a real
// gVisor install. It is exported (not a _test.go file) specifically so
// both packages' test suites can share one fake instead of each
// hand-rolling their own.
package runtimetest

import (
	"context"
	"fmt"
	"sync"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/runtime"
)

// Fake is a ContainerRuntime whose behavior is entirely driven by the
// fields/hooks below, set by the test before use.
type Fake struct {
	mu sync.Mutex

	// CanaryDenial is what ProbeSyscall returns for compile.CanarySyscall.
	// Defaults to the "confinement working correctly" case: denied with
	// EPERM via seccomp. Tests that want to simulate a broken confinement
	// layer (the exact scenario the canary check exists to catch) set this
	// to something else.
	CanaryDenial runtime.Denial

	// ExecFunc, if set, is called by Exec so a test can script denials,
	// errors, or payload contents per request. Defaults to a clean,
	// no-denial success.
	ExecFunc func(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error)

	// CreateErr / CreateUnconfinedErr / DestroyErr, if set, are returned
	// verbatim by the corresponding method.
	CreateErr           error
	CreateUnconfinedErr error
	DestroyErr          error

	created           map[string]bool
	createdUnconfined map[string]bool
	destroyed         map[string]bool
}

// New returns a Fake configured to behave like confinement is working:
// the canary syscall is denied via seccomp with EPERM, and Exec succeeds
// cleanly by default.
func New() *Fake {
	return &Fake{
		CanaryDenial: runtime.Denial{
			Occurred: true,
			Kind:     runtime.DenialKindSeccomp,
			Detail:   compile.CanarySyscall,
			Errno:    1, // EPERM
		},
		created:           map[string]bool{},
		createdUnconfined: map[string]bool{},
		destroyed:         map[string]bool{},
	}
}

func (f *Fake) Create(ctx context.Context, id string, policy *compile.CompiledPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.CreateErr != nil {
		return f.CreateErr
	}
	f.created[id] = true
	return nil
}

func (f *Fake) CreateUnconfined(ctx context.Context, id string, policy *compile.CompiledPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.CreateUnconfinedErr != nil {
		return f.CreateUnconfinedErr
	}
	f.createdUnconfined[id] = true
	return nil
}

func (f *Fake) ProbeSyscall(ctx context.Context, id string, syscallName string) (runtime.Denial, error) {
	if syscallName != compile.CanarySyscall {
		return runtime.Denial{}, fmt.Errorf("runtimetest: fake only knows how to probe the canary syscall, got %q", syscallName)
	}
	return f.CanaryDenial, nil
}

func (f *Fake) Exec(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
	if f.ExecFunc != nil {
		return f.ExecFunc(ctx, id, req)
	}
	return runtime.ExecResult{Status: "SUCCESS"}, nil
}

func (f *Fake) Destroy(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DestroyErr != nil {
		return f.DestroyErr
	}
	f.destroyed[id] = true
	return nil
}

func (f *Fake) WasCreated(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created[id]
}

func (f *Fake) WasCreatedUnconfined(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createdUnconfined[id]
}

func (f *Fake) WasDestroyed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.destroyed[id]
}

var _ runtime.ContainerRuntime = (*Fake)(nil)
