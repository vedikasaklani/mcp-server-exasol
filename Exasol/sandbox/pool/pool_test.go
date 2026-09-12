package pool_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/metrics"
	"mcp-warden/sandbox/pool"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runtimetest"
)

func testPolicy() *compile.CompiledPolicy {
	eperm := uint(1)
	return &compile.CompiledPolicy{
		ToolNames: []string{"t"},
		Seccomp: &specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: &eperm,
			Syscalls:        []specs.LinuxSyscall{{Names: []string{"read"}, Action: specs.ActAllow}},
		},
	}
}

func newPool(t *testing.T, fake *runtimetest.Fake, cfg pool.Config) (*pool.Pool, *metrics.Registry) {
	t.Helper()
	reg := metrics.NewRegistry()
	sup := runtime.NewEnforcingSupervisor(fake)
	p, err := pool.New(context.Background(), sup, testPolicy(), cfg, reg)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p, reg
}

func TestPool_WarmsToConfiguredSize(t *testing.T) {
	fake := runtimetest.New()
	_, reg := newPool(t, fake, pool.Config{Size: 3})

	if got := reg.Counter("warden_containers_created_total").Value(); got != 3 {
		t.Fatalf("created %d containers, want 3 warmed up front", got)
	}
	if got := reg.Gauge("warden_pool_idle").Value(); got != 3 {
		t.Fatalf("idle gauge = %d, want 3", got)
	}
}

func TestPool_CreationFailureTearsDownAndReportsRatherThanStartingSmall(t *testing.T) {
	fake := runtimetest.New()
	// Confinement cannot be verified — every container must be refused.
	fake.CanaryDenial = runtime.Denial{Occurred: false}

	reg := metrics.NewRegistry()
	sup := runtime.NewEnforcingSupervisor(fake)
	_, err := pool.New(context.Background(), sup, testPolicy(), pool.Config{Size: 2}, reg)
	if err == nil {
		t.Fatalf("a pool that cannot confine its containers must fail to start, not start degraded")
	}
}

func TestPool_DoRunsRequestAndReturnsContainer(t *testing.T) {
	fake := runtimetest.New()
	p, reg := newPool(t, fake, pool.Config{Size: 1})

	res, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: "r1"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != "SUCCESS" {
		t.Fatalf("status = %q", res.Status)
	}
	if got := reg.Counter("warden_requests_total").Value(); got != 1 {
		t.Fatalf("requests_total = %d, want 1", got)
	}
	// Container came back, so a second request works against the same pool
	// of one.
	if _, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: "r2"}); err != nil {
		t.Fatalf("second Do: %v", err)
	}
	if got := reg.Counter("warden_containers_created_total").Value(); got != 1 {
		t.Fatalf("created %d containers, want 1 reused (no per-request creation)", got)
	}
}

func TestPool_QuarantinedContainerIsDiscardedAndReplaced(t *testing.T) {
	fake := runtimetest.New()
	fake.ExecFunc = func(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
		return runtime.ExecResult{
			Status: "DENIED",
			Denial: runtime.Denial{Occurred: true, Kind: runtime.DenialKindSeccomp, Detail: "ptrace", Errno: 1},
		}, nil
	}
	p, reg := newPool(t, fake, pool.Config{Size: 1})

	if _, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: "r1"}); err == nil {
		t.Fatalf("a kernel denial must surface as an error")
	}
	if got := reg.Counter("warden_kernel_denials_total").Value(); got != 1 {
		t.Fatalf("kernel_denials_total = %d, want 1", got)
	}
	if got := reg.Counter("warden_containers_quarantined_total").Value(); got != 1 {
		t.Fatalf("quarantined_total = %d, want 1", got)
	}

	// A replacement is created in the background; capacity must recover.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Counter("warden_containers_created_total").Value() >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("quarantined container was never replaced; created=%d",
		reg.Counter("warden_containers_created_total").Value())
}

func TestPool_RetiresContainerAfterMaxRequests(t *testing.T) {
	fake := runtimetest.New()
	p, reg := newPool(t, fake, pool.Config{Size: 1, MaxRequestsPerContainer: 2})

	for i := 0; i < 2; i++ {
		if _, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: fmt.Sprint(i)}); err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Counter("warden_containers_retired_total").Value() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("container was not retired after reaching its request cap")
}

func TestPool_AcquireTimesOutWhenSaturated(t *testing.T) {
	fake := runtimetest.New()
	release := make(chan struct{})
	fake.ExecFunc = func(ctx context.Context, id string, req runtime.ExecRequest) (runtime.ExecResult, error) {
		<-release
		return runtime.ExecResult{Status: "SUCCESS"}, nil
	}
	p, reg := newPool(t, fake, pool.Config{Size: 1, AcquireTimeout: 50 * time.Millisecond})

	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = p.Do(context.Background(), runtime.ExecRequest{RequestID: "slow"})
	}()
	<-started
	time.Sleep(20 * time.Millisecond) // let the goroutine take the only container

	_, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: "blocked"})
	close(release)
	if err == nil {
		t.Fatalf("expected saturation to surface as a timeout, not an unbounded wait")
	}
	if got := reg.Counter("warden_pool_acquire_timeouts_total").Value(); got != 1 {
		t.Fatalf("acquire_timeouts_total = %d, want 1", got)
	}
}

func TestPool_ServesConcurrentRequestsWithoutRaces(t *testing.T) {
	fake := runtimetest.New()
	p, reg := newPool(t, fake, pool.Config{Size: 4})

	const workers, each = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := p.Do(context.Background(), runtime.ExecRequest{RequestID: fmt.Sprintf("%d-%d", w, i)}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent request failed: %v", err)
	}

	if got := reg.Counter("warden_requests_total").Value(); got != workers*each {
		t.Fatalf("requests_total = %d, want %d", got, workers*each)
	}
	// The whole point of the pool: no per-request container creation.
	if got := reg.Counter("warden_containers_created_total").Value(); got != 4 {
		t.Fatalf("created %d containers for %d requests, want 4", got, workers*each)
	}
}

func TestPool_CloseDestroysEveryContainer(t *testing.T) {
	fake := runtimetest.New()
	reg := metrics.NewRegistry()
	sup := runtime.NewEnforcingSupervisor(fake)
	p, err := pool.New(context.Background(), sup, testPolicy(), pool.Config{Size: 3}, reg)
	if err != nil {
		t.Fatalf("pool.New: %v", err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := reg.Counter("warden_containers_destroyed_total").Value(); got != 3 {
		t.Fatalf("destroyed %d, want 3", got)
	}
	if _, err := p.Acquire(context.Background()); err != pool.ErrClosed {
		t.Fatalf("Acquire after Close = %v, want ErrClosed", err)
	}
}

func TestPool_CloseIsIdempotent(t *testing.T) {
	fake := runtimetest.New()
	p, _ := newPool(t, fake, pool.Config{Size: 1})
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
}
