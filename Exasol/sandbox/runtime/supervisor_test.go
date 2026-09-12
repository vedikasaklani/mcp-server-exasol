package runtime_test

import (
	"context"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runtimetest"
)

func samplePolicy() *compile.CompiledPolicy {
	epermRet := uint(1)
	return &compile.CompiledPolicy{
		ToolNames: []string{"query_metrics"},
		Seccomp: &specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: &epermRet,
			Syscalls:        []specs.LinuxSyscall{{Names: []string{"read", "write"}, Action: specs.ActAllow}},
		},
	}
}

func TestNewContainer_ReachesReadyWhenConfinementVerified(t *testing.T) {
	fake := runtimetest.New()
	sup := runtime.NewEnforcingSupervisor(fake)

	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.State() != runtime.StateReady {
		t.Fatalf("state = %v, want READY", c.State())
	}
	if !fake.WasCreated(c.ID()) {
		t.Fatalf("Create was never called for container %s", c.ID())
	}
}

func TestNewContainer_RejectsWhenCanaryNotDenied(t *testing.T) {
	fake := runtimetest.New()
	// Simulate the exact failure the canary exists to catch: the kernel
	// let the canary syscall through instead of denying it.
	fake.CanaryDenial = runtime.Denial{Occurred: false}
	sup := runtime.NewEnforcingSupervisor(fake)

	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err == nil {
		t.Fatalf("expected error when canary syscall is not denied")
	}
	if c != nil {
		t.Fatalf("expected nil container on canary failure, got %+v", c)
	}
}

func TestNewContainer_RejectsWhenCanaryDeniedWithWrongErrno(t *testing.T) {
	fake := runtimetest.New()
	fake.CanaryDenial = runtime.Denial{Occurred: true, Kind: runtime.DenialKindSeccomp, Errno: 38 /* ENOSYS */}
	sup := runtime.NewEnforcingSupervisor(fake)

	_, err := sup.NewContainer(context.Background(), samplePolicy())
	if err == nil || !strings.Contains(err.Error(), "EPERM") {
		t.Fatalf("expected EPERM mismatch error, got %v", err)
	}
}

func TestNewContainer_PropagatesCreateError(t *testing.T) {
	fake := runtimetest.New()
	fake.CreateErr = context.DeadlineExceeded
	sup := runtime.NewEnforcingSupervisor(fake)

	_, err := sup.NewContainer(context.Background(), samplePolicy())
	if err == nil {
		t.Fatalf("expected error when Create fails")
	}
}

func TestExecute_ReturnsToReadyOnCleanExecution(t *testing.T) {
	fake := runtimetest.New()
	sup := runtime.NewEnforcingSupervisor(fake)
	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	res, err := sup.Execute(context.Background(), c, runtime.ExecRequest{RequestID: "req_1", ToolName: "query_metrics"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != "SUCCESS" {
		t.Fatalf("status = %q, want SUCCESS", res.Status)
	}
	if c.State() != runtime.StateReady {
		t.Fatalf("state after clean exec = %v, want READY", c.State())
	}
}

func TestExecute_QuarantinesOnKernelDenial(t *testing.T) {
	fake := runtimetest.New()
	fake.ExecFunc = func(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
		return runtime.ExecResult{
			Status: "DENIED",
			Denial: runtime.Denial{Occurred: true, Kind: runtime.DenialKindLandlock, Detail: "/etc/shadow", Errno: 13},
		}, nil
	}
	sup := runtime.NewEnforcingSupervisor(fake)
	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err = sup.Execute(context.Background(), c, runtime.ExecRequest{RequestID: "req_2", ToolName: "query_metrics"})
	if err == nil {
		t.Fatalf("expected error on kernel denial")
	}
	if c.State() != runtime.StateQuarantined {
		t.Fatalf("state after denial = %v, want QUARANTINED", c.State())
	}
}

func TestExecute_RefusesConcurrentCallOnSameContainer(t *testing.T) {
	fake := runtimetest.New()
	started := make(chan struct{})
	release := make(chan struct{})
	fake.ExecFunc = func(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
		close(started)
		<-release
		return runtime.ExecResult{Status: "SUCCESS"}, nil
	}
	sup := runtime.NewEnforcingSupervisor(fake)
	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	firstErr := make(chan error, 1)
	go func() {
		_, err := sup.Execute(context.Background(), c, runtime.ExecRequest{RequestID: "req_a"})
		firstErr <- err
	}()

	<-started // first call is now in-flight, container is in EXECUTING
	if c.State() != runtime.StateExecuting {
		t.Fatalf("state while in-flight = %v, want EXECUTING", c.State())
	}

	// §6.3: "one in-flight tool call per container." A second call while
	// the first is still running must be refused by the state machine
	// itself (READY -> EXECUTING is the only legal entry), not merely by
	// caller discipline.
	_, err = sup.Execute(context.Background(), c, runtime.ExecRequest{RequestID: "req_b"})
	if err == nil {
		t.Fatalf("expected second concurrent Execute to be refused")
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if c.State() != runtime.StateReady {
		t.Fatalf("state after first exec completes = %v, want READY", c.State())
	}
}

func TestDestroy_TearsDownAndMarksTerminal(t *testing.T) {
	fake := runtimetest.New()
	sup := runtime.NewEnforcingSupervisor(fake)
	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := sup.Destroy(context.Background(), c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.State() != runtime.StateDestroyed {
		t.Fatalf("state = %v, want DESTROYED", c.State())
	}
	if !fake.WasDestroyed(c.ID()) {
		t.Fatalf("Destroy was never called on the backend")
	}
}

func TestDestroy_IsIllegalOnAlreadyDestroyedContainer(t *testing.T) {
	fake := runtimetest.New()
	sup := runtime.NewEnforcingSupervisor(fake)
	c, err := sup.NewContainer(context.Background(), samplePolicy())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := sup.Destroy(context.Background(), c); err != nil {
		t.Fatalf("first destroy: %v", err)
	}
	if err := sup.Destroy(context.Background(), c); err == nil {
		t.Fatalf("expected error destroying an already-destroyed container")
	}
}

func TestMode_IsHardcodedPerSupervisorType(t *testing.T) {
	sup := runtime.NewEnforcingSupervisor(runtimetest.New())
	if sup.Mode() != runtime.ModeEnforcing {
		t.Fatalf("Mode() = %v, want ModeEnforcing", sup.Mode())
	}
}
