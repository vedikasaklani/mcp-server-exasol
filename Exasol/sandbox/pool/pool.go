// Package pool keeps a set of confined containers warm and ready, so the
// cost of creating one never lands on a request.
//
// Container creation measured ~220ms against a real gVisor install: gVisor
// boot, mount setup, and the canary verification handshake. That is fine
// once per session and unacceptable per call, which is exactly the concern
// the sandbox design note raised (flag #6: container start latency versus
// the §1 latency budget). A pool converts it into a startup cost paid
// once, plus a background replacement cost paid only when a container is
// retired.
//
// The pool is also where §6.2's quarantine transition becomes operationally
// real: a container that hits a kernel denial is never reused. It is
// destroyed and replaced, and the session that touched it does not get to
// contaminate the next one.
package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/metrics"
	"mcp-warden/sandbox/runtime"
)

// ErrClosed is returned by Acquire once the pool is shutting down.
var ErrClosed = errors.New("pool: closed")

// Supervisor is the subset of runtime.EnforcingSupervisor the pool needs.
// Narrow on purpose: the pool must not be able to reach the unconfined
// (learning-mode) creation path even by accident.
type Supervisor interface {
	NewContainer(ctx context.Context, policy *compile.CompiledPolicy) (*runtime.Container, error)
	Execute(ctx context.Context, c *runtime.Container, req runtime.ExecRequest) (runtime.ExecResult, error)
	Destroy(ctx context.Context, c *runtime.Container) error
}

// Observer receives the lifecycle and request events a behavioural
// analyzer needs in order to attribute syscalls to requests.
//
// It is an interface on the pool rather than a dependency of it because
// the pool must keep working — and keep confining — whether or not
// anything is watching. A nil Observer disables analysis and changes
// nothing else.
type Observer interface {
	// ContainerStarted is called after a container has been confined and
	// verified, before it serves anything.
	ContainerStarted(containerID string)
	// ContainerStopped is called once a container will never serve again.
	ContainerStopped(containerID string)
	// RequestStarted brackets the beginning of one tool call. §6.3
	// serializes calls per container, so the interval between this and
	// RequestFinished attributes syscalls to exactly one request.
	RequestStarted(containerID string, req runtime.ExecRequest)
	// RequestFinished closes that interval.
	RequestFinished(containerID string, req runtime.ExecRequest, out RequestOutcome)
}

// RequestOutcome is what the pool observed about a completed call.
type RequestOutcome struct {
	ResponseBytes int
	Response      []byte
	Unsolicited   int
	Failed        bool
	Denial        string
	Latency       time.Duration
	// Synthetic marks a proxy-initiated exchange (the warmup handshake)
	// rather than a call from a client.
	Synthetic bool
}

// Config configures a Pool.
type Config struct {
	// Observer, if set, receives container and request lifecycle events
	// for behavioural analysis. Optional.
	Observer Observer
	// Size is how many warm containers to keep. Each one holds a running
	// server process, so this is a memory/latency tradeoff, not a free
	// dial.
	Size int
	// MaxRequestsPerContainer retires a container after it has served this
	// many requests, if > 0. Bounding reuse limits how much state one
	// compromised or leaky session can accumulate — a cheap approximation
	// of the ephemerality §6.2 asks for, without paying full container
	// creation per call.
	MaxRequestsPerContainer int
	// AcquireTimeout bounds how long a caller waits for a free container
	// before being told the system is saturated. Zero means wait until the
	// caller's own context expires.
	AcquireTimeout time.Duration
	// Warmup runs against every new container before it joins the idle
	// set. For MCP this is the protocol handshake — initialize, then the
	// initialized notification, then tools/list.
	//
	// It is not optional bookkeeping. Each container runs its own server
	// process, so each holds its own protocol state; a client's single
	// initialize would reach exactly one of them and every other
	// container in the pool would reject the first real call. Running the
	// handshake at creation is what makes pooling compatible with a
	// stateful stdio protocol at all.
	Warmup []runtime.ExecRequest
	// OnWarmupResponse receives each warmup response, in order. The
	// manifest hash (§4.2) is pinned from the tools/list response here.
	OnWarmupResponse func(containerID string, req runtime.ExecRequest, res runtime.ExecResult)
}

// Pool owns a set of warm confined containers.
type Pool struct {
	sup     Supervisor
	policy  *compile.CompiledPolicy
	cfg     Config
	metrics *metrics.Registry

	idle chan *entry

	mu      sync.Mutex
	live    map[*runtime.Container]*entry
	closed  bool
	closing chan struct{}
	wg      sync.WaitGroup
}

type entry struct {
	container *runtime.Container
	served    int
}

// New creates the pool and warms it to Size containers. If any container
// fails to confine, New tears down whatever it already created and
// returns the error: a pool that silently starts smaller than requested
// is a pool that hides a confinement failure.
func New(ctx context.Context, sup Supervisor, policy *compile.CompiledPolicy, cfg Config, reg *metrics.Registry) (*Pool, error) {
	if cfg.Size <= 0 {
		cfg.Size = 1
	}
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	p := &Pool{
		sup:     sup,
		policy:  policy,
		cfg:     cfg,
		metrics: reg,
		idle:    make(chan *entry, cfg.Size),
		live:    map[*runtime.Container]*entry{},
		closing: make(chan struct{}),
	}

	for i := 0; i < cfg.Size; i++ {
		e, err := p.create(ctx)
		if err != nil {
			_ = p.Close(context.Background())
			return nil, fmt.Errorf("pool: warm container %d/%d: %w", i+1, cfg.Size, err)
		}
		p.idle <- e
	}
	p.metrics.Gauge("warden_pool_size").Set(int64(cfg.Size))
	p.metrics.Gauge("warden_pool_idle").Set(int64(len(p.idle)))
	return p, nil
}

func (p *Pool) create(ctx context.Context) (*entry, error) {
	start := time.Now()
	c, err := p.sup.NewContainer(ctx, p.policy)
	if err != nil {
		p.metrics.Counter("warden_container_create_failures_total").Inc()
		return nil, err
	}
	p.metrics.Histogram("warden_container_create_seconds").Observe(time.Since(start))
	p.metrics.Counter("warden_containers_created_total").Inc()

	if p.cfg.Observer != nil {
		p.cfg.Observer.ContainerStarted(c.ID())
	}

	for i, req := range p.cfg.Warmup {
		if p.cfg.Observer != nil {
			p.cfg.Observer.RequestStarted(c.ID(), req)
		}
		wstart := time.Now()
		res, werr := p.sup.Execute(ctx, c, req)
		if p.cfg.Observer != nil {
			p.cfg.Observer.RequestFinished(c.ID(), req, RequestOutcome{
				ResponseBytes: len(res.Payload), Response: res.Payload,
				Unsolicited: len(res.Unsolicited), Failed: werr != nil,
				Latency: time.Since(wstart), Synthetic: true,
			})
		}
		if werr != nil {
			// A container that cannot complete its handshake cannot
			// serve. Destroying it and failing is the fail-closed
			// behaviour §6.2 requires; adding it to the pool anyway would
			// hand a broken container to a real request later.
			p.metrics.Counter("warden_container_warmup_failures_total").Inc()
			dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = p.sup.Destroy(dctx, c)
			dcancel()
			if p.cfg.Observer != nil {
				p.cfg.Observer.ContainerStopped(c.ID())
			}
			return nil, fmt.Errorf("pool: container %s failed warmup step %d/%d: %w", c.ID(), i+1, len(p.cfg.Warmup), werr)
		}
		if p.cfg.OnWarmupResponse != nil {
			p.cfg.OnWarmupResponse(c.ID(), req, res)
		}
	}

	e := &entry{container: c}
	p.mu.Lock()
	p.live[c] = e
	p.mu.Unlock()
	return e, nil
}

// Acquire checks out a warm container. The caller must return it via
// Release (healthy) or Discard (quarantined).
func (p *Pool) Acquire(ctx context.Context) (*runtime.Container, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	start := time.Now()
	var timeout <-chan time.Time
	if p.cfg.AcquireTimeout > 0 {
		t := time.NewTimer(p.cfg.AcquireTimeout)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case e := <-p.idle:
		p.metrics.Histogram("warden_pool_acquire_wait_seconds").Observe(time.Since(start))
		p.metrics.Gauge("warden_pool_idle").Set(int64(len(p.idle)))
		p.metrics.Gauge("warden_pool_in_use").Add(1)
		return e.container, nil
	case <-p.closing:
		return nil, ErrClosed
	case <-timeout:
		p.metrics.Counter("warden_pool_acquire_timeouts_total").Inc()
		return nil, fmt.Errorf("pool: no container available within %s (all %d in use)", p.cfg.AcquireTimeout, p.cfg.Size)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Release returns a healthy container to the pool, retiring and replacing
// it if it has served its configured maximum.
func (p *Pool) Release(c *runtime.Container) {
	p.metrics.Gauge("warden_pool_in_use").Add(-1)

	p.mu.Lock()
	e, ok := p.live[c]
	closed := p.closed
	p.mu.Unlock()
	if !ok || closed {
		return
	}

	e.served++
	if p.cfg.MaxRequestsPerContainer > 0 && e.served >= p.cfg.MaxRequestsPerContainer {
		p.metrics.Counter("warden_containers_retired_total").Inc()
		p.retire(c)
		return
	}

	select {
	case p.idle <- e:
		p.metrics.Gauge("warden_pool_idle").Set(int64(len(p.idle)))
	default:
		// Pool already full (a replacement landed first); this one is
		// surplus and gets destroyed rather than leaked.
		p.retire(c)
	}
}

// Discard removes a container that must never serve again — a quarantined
// one — and starts a replacement. §3.3/§5: quarantine is instance-scoped,
// so this affects exactly this container, not the artifact or its siblings.
func (p *Pool) Discard(c *runtime.Container) {
	p.metrics.Gauge("warden_pool_in_use").Add(-1)
	p.metrics.Counter("warden_containers_quarantined_total").Inc()
	p.retire(c)
}

// retire destroys a container and, unless the pool is closing, replaces it
// in the background so capacity recovers without blocking a caller.
func (p *Pool) retire(c *runtime.Container) {
	p.mu.Lock()
	delete(p.live, c)
	closed := p.closed
	p.mu.Unlock()

	if p.cfg.Observer != nil {
		p.cfg.Observer.ContainerStopped(c.ID())
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = p.sup.Destroy(ctx, c)
		p.metrics.Counter("warden_containers_destroyed_total").Inc()

		if closed {
			return
		}
		e, err := p.create(ctx)
		if err != nil {
			// Capacity is now below Size. That is visible in
			// warden_pool_size vs the created/destroyed counters rather
			// than being silently absorbed.
			p.metrics.Gauge("warden_pool_degraded").Set(1)
			return
		}
		select {
		case p.idle <- e:
			p.metrics.Gauge("warden_pool_idle").Set(int64(len(p.idle)))
		case <-p.closing:
			dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer dcancel()
			_ = p.sup.Destroy(dctx, e.container)
		}
	}()
}

// Do acquires a container, runs one request against it, and returns it to
// the pool — releasing on success, discarding on any failure. Callers
// should prefer this over Acquire/Release: "discard on error" is the
// fail-closed behavior §6.2 requires, and making it the default path means
// forgetting it isn't possible.
func (p *Pool) Do(ctx context.Context, req runtime.ExecRequest) (runtime.ExecResult, error) {
	c, err := p.Acquire(ctx)
	if err != nil {
		return runtime.ExecResult{}, err
	}

	obs := p.cfg.Observer
	if obs != nil {
		obs.RequestStarted(c.ID(), req)
	}
	start := time.Now()
	res, err := p.sup.Execute(ctx, c, req)
	elapsed := time.Since(start)
	p.metrics.Histogram("warden_request_seconds").Observe(elapsed)
	p.metrics.Counter("warden_requests_total").Inc()

	if obs != nil {
		out := RequestOutcome{
			ResponseBytes: len(res.Payload),
			Response:      res.Payload,
			Unsolicited:   len(res.Unsolicited),
			Failed:        err != nil,
			Latency:       elapsed,
		}
		if res.Denial.Occurred {
			out.Denial = string(res.Denial.Kind) + " " + res.Denial.Detail
		}
		obs.RequestFinished(c.ID(), req, out)
	}

	// EnforcingSupervisor.Execute already turns a kernel denial into an
	// error (and quarantines), so the denial has to be recognized on the
	// error path — checking it only on the success path would count zero
	// denials forever.
	if err != nil {
		if res.Denial.Occurred {
			p.metrics.Counter("warden_kernel_denials_total").Inc()
		}
		p.metrics.Counter("warden_request_failures_total").Inc()
		p.Discard(c)
		return res, err
	}
	if n := len(res.Unsolicited); n > 0 {
		p.metrics.Counter("warden_unsolicited_messages_total").Add(int64(n))
	}
	p.Release(c)
	return res, nil
}

// Close destroys every container the pool owns and waits for in-flight
// replacements to finish.
func (p *Pool) Close(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.closing)
	containers := make([]*runtime.Container, 0, len(p.live))
	for c := range p.live {
		containers = append(containers, c)
	}
	p.live = map[*runtime.Container]*entry{}
	p.mu.Unlock()

	var firstErr error
	for _, c := range containers {
		if err := p.sup.Destroy(ctx, c); err != nil && firstErr == nil {
			firstErr = err
		}
		p.metrics.Counter("warden_containers_destroyed_total").Inc()
	}
	p.wg.Wait()
	p.metrics.Gauge("warden_pool_idle").Set(0)
	p.metrics.Gauge("warden_pool_size").Set(0)
	return firstErr
}

// Metrics returns the registry the pool reports into.
func (p *Pool) Metrics() *metrics.Registry { return p.metrics }
