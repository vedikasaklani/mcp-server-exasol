// Command warden-serve is the long-running warden daemon: it keeps a pool
// of confined MCP server containers warm, serves JSON-RPC requests against
// them over HTTP, and exposes live metrics while traffic is flowing.
//
//	warden-serve -profile srv.json -probe ./probe -pool 4 -- <server cmd>
//
// Endpoints:
//
//	POST /rpc        one JSON-RPC request body -> the response from a confined server
//	GET  /metrics    Prometheus text exposition
//	GET  /stats      JSON metrics snapshot
//	GET  /healthz    readiness (200 only while the pool can serve)
//	GET  /findings   behavioural findings, most severe first
//	GET  /score      security posture + reliability, kept apart per §7.2
//	GET  /narrative  findings correlated across families into a summary
//	GET  /behavior   full analysis snapshot
//	GET  /containers per-container drill-down
//	GET  /audit      tail of the hash-chained audit log
//	GET  /         live dashboard, refreshes itself
//
// Container creation costs ~220ms against a real gVisor install. The pool
// pays that at startup and on replacement, never on a request, which is
// what makes a per-call sandbox viable under sustained load.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/audit"
	"mcp-warden/sandbox/bridge"
	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/metrics"
	"mcp-warden/sandbox/pool"
	"mcp-warden/sandbox/profile"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runsc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden-serve:", err)
		os.Exit(1)
	}
}

type server struct {
	pool    *pool.Pool
	reg     *metrics.Registry
	mon     *analyze.Monitor
	audit   *audit.Log
	ready   atomic.Bool
	timeout time.Duration
	target  string
	digest  string
	session string
	addr    string
	rt      *runsc.Runtime
	poolN   int
	tracing bool
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-serve", flag.ContinueOnError)
	profilePath := fs.String("profile", "", "path to an approved CapabilityProfile JSON (required)")
	probePath := fs.String("probe", "", "path to the built probe binary (required)")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	poolSize := fs.Int("pool", 2, "number of warm confined containers to keep")
	maxPerContainer := fs.Int("max-requests-per-container", 0, "retire a container after N requests (0 = unlimited)")
	acquireTimeout := fs.Duration("acquire-timeout", 5*time.Second, "how long a request waits for a free container before 503")
	reqTimeout := fs.Duration("request-timeout", 30*time.Second, "per-request timeout")
	memLimit := fs.Int64("memory-bytes", 0, "per-container memory cap (0 = default)")
	pidLimit := fs.Int64("pid-limit", 0, "per-container process cap (0 = default)")
	analyzeMode := fs.String("analyze", "detect", "behavioural analysis: off | detect (curated syscall set) | full (every syscall, slower)")
	auditPath := fs.String("audit", "", "path to the hash-chained audit log (empty disables it)")
	sessionID := fs.String("session", "", "session id stamped on audit entries (default: generated)")
	evalEvery := fs.Duration("evaluate-every", 2*time.Second, "how often detectors run over the live session")
	traceCap := fs.Int64("trace-max-bytes", 512<<20, "truncate a container's trace log past this size")
	noHandshake := fs.Bool("no-handshake", false, "skip the MCP initialize/tools-list handshake on each new container")
	live := fs.Bool("live", false, "render a live terminal dashboard and keep running until interrupted")
	refresh := fs.Duration("refresh", time.Second, "live dashboard refresh interval")
	cwd := fs.String("cwd", "", "working directory for the confined process inside the guest (default: none)")
	drivePath := fs.String("drive", "", "replay this newline-delimited JSON-RPC file against the server on a loop")
	driveRate := fs.Float64("rate", 2, "requests per second when -drive is set")
	var extraEnv stringList
	fs.Var(&extraEnv, "env", "extra KEY=VALUE for the confined process (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("no command given; usage: warden-serve -profile p.json -probe probe -- <command> [args...]")
	}
	if *profilePath == "" || *probePath == "" {
		return fmt.Errorf("-profile and -probe are both required")
	}

	prof, err := profile.Load(*profilePath)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}
	policy, err := compile.Session(prof, compile.Options{})
	if err != nil {
		return fmt.Errorf("compile session policy: %w", err)
	}
	if resolved, lookErr := exec.LookPath(command[0]); lookErr == nil {
		command[0] = resolved
	}

	bundleRoot, err := os.MkdirTemp("", "warden-serve-")
	if err != nil {
		return fmt.Errorf("create bundle root: %w", err)
	}
	defer os.RemoveAll(bundleRoot)
	rootfs, err := os.MkdirTemp("", "warden-rootfs-")
	if err != nil {
		return fmt.Errorf("create rootfs: %w", err)
	}
	defer os.RemoveAll(rootfs)

	limits := runsc.DefaultLimits()
	if *memLimit > 0 {
		limits.MemoryBytes = *memLimit
	}
	if *pidLimit > 0 {
		limits.PIDLimit = *pidLimit
	}

	env := append([]string{
		"PATH=/usr/bin:/bin",
		"HOME=/tmp/scratch",
		"TMPDIR=/tmp/scratch",
	}, extraEnv...)

	rt := &runsc.Runtime{
		BundleRoot:      bundleRoot,
		Rootfs:          runsc.BundleConfig{RootfsPath: rootfs, Args: command, Env: env, Cwd: *cwd},
		ProbeBinaryPath: *probePath,
		Limits:          limits,
	}
	switch *analyzeMode {
	case "off":
	case "detect":
		rt.Trace = true
		rt.TraceSyscalls = runsc.DetectionSyscalls
	case "full":
		rt.Trace = true
	default:
		return fmt.Errorf("-analyze must be off, detect or full (got %q)", *analyzeMode)
	}

	reg := metrics.NewRegistry()
	sup := runtime.NewEnforcingSupervisor(rt)

	sess := *sessionID
	if sess == "" {
		sess = newSessionID()
	}

	var auditLog *audit.Log
	if *auditPath != "" {
		auditLog, err = audit.Open(audit.Config{
			Path: *auditPath, SessionID: sess,
			ServerID: filepath.Base(command[0]), ImageDigest: prof.ImageDigest,
			// Enforcing, not learning. If this daemon ever grows an
			// unconfined mode it must set this, and the flag must come
			// from the supervisor's own Mode rather than from a flag a
			// caller can get wrong.
			LearningMode: sup.Mode() != runtime.ModeEnforcing,
		})
		if err != nil {
			return fmt.Errorf("open audit chain: %w", err)
		}
		fmt.Printf("audit chain: %s (verify with: warden-audit -verify %s)\n", *auditPath, *auditPath)
	}

	baseline := analyze.BaselineFromProfile(prof)
	var obs *bridge.Observer
	mon := analyze.NewMonitor(analyze.MonitorConfig{
		Baseline:                  baseline,
		Locate:                    rt.TraceDir,
		EvaluateEvery:             *evalEvery,
		MaxTraceBytesPerContainer: *traceCap,
		OnFinding:                 func(id string, f analyze.Finding) { obs.OnFinding(id, f) },
	})
	obs = bridge.New(mon, auditLog)

	// Measure what is actually going to run, before anything runs. This
	// is the only check that can fail before a single request is served,
	// and the only one that covers the ELF interpreter — code that runs
	// in every dynamically linked process and appears in no syscall
	// trace.
	entry := analyze.MeasureEntrypoint(command[0])
	mon.SetEntrypoint(entry)
	if entry.SHA256 != "" {
		fmt.Printf("entrypoint %s = %s\n", entry.Path, entry.SHA256)
		if entry.Interpreter != "" {
			fmt.Printf("interpreter %s = %s\n", entry.Interpreter, entry.InterpreterSHA256)
		}
	}
	if auditLog != nil {
		auditLog.Append(audit.Entry{
			Kind: audit.KindLifecycle,
			Lifecycle: &audit.Lifecycle{
				Event:  "session_start",
				Detail: fmt.Sprintf("target=%s entrypoint=%s interp=%s analyze=%s", strings.Join(command, " "), entry.SHA256, entry.InterpreterSHA256, *analyzeMode),
			},
		})
	}

	fmt.Printf("warming %d confined container(s)...\n", *poolSize)
	warmStart := time.Now()
	var warmup []runtime.ExecRequest
	if !*noHandshake {
		warmup = bridge.Handshake(*reqTimeout)
	}
	p, err := pool.New(context.Background(), sup, policy, pool.Config{
		Size:                    *poolSize,
		MaxRequestsPerContainer: *maxPerContainer,
		AcquireTimeout:          *acquireTimeout,
		Observer:                obs,
		Warmup:                  warmup,
		OnWarmupResponse: func(containerID string, req runtime.ExecRequest, res runtime.ExecResult) {
			// tools/list is where the manifest is pinned (§4.2 step 3).
			mon.ObserveResponse(containerID, res.Payload)
		},
	}, reg)
	if err != nil {
		return fmt.Errorf("warm pool (a sandbox that cannot be verified must not serve traffic): %w", err)
	}
	fmt.Printf("pool ready in %v\n", time.Since(warmStart))
	if filterDropped, tracingDropped := rt.TraceDegraded(); filterDropped || tracingDropped {
		// Confinement is unaffected either way; say plainly what was lost
		// so nobody reads a quiet findings list as a clean bill of health.
		switch {
		case tracingDropped:
			fmt.Println("WARNING: this runsc would not start a traced container; behavioural analysis is OFF (confinement is still enforced).")
		default:
			fmt.Println("NOTE: this runsc rejected the syscall trace filter; tracing every syscall instead (higher overhead, same coverage).")
		}
	}

	srv := &server{
		pool:    p,
		reg:     reg,
		mon:     mon,
		audit:   auditLog,
		timeout: *reqTimeout,
		target:  strings.Join(command, " "),
		digest:  prof.ImageDigest,
		session: sess,
		addr:    *addr,
		rt:      rt,
		poolN:   *poolSize,
		tracing: rt.Trace,
	}
	srv.ready.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", srv.handleRPC)
	mux.HandleFunc("/metrics", srv.handleMetrics)
	mux.HandleFunc("/stats", srv.handleStats)
	mux.HandleFunc("/healthz", srv.handleHealth)
	mux.HandleFunc("/findings", srv.handleFindings)
	mux.HandleFunc("/score", srv.handleScore)
	mux.HandleFunc("/narrative", srv.handleNarrative)
	mux.HandleFunc("/behavior", srv.handleBehavior)
	mux.HandleFunc("/containers", srv.handleContainers)
	mux.HandleFunc("/audit", srv.handleAudit)
	mux.HandleFunc("/", srv.handleDashboard)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Detectors run on a ticker rather than per request: gVisor writes
	// its debug log asynchronously, so a request's events routinely
	// arrive after that request has returned.
	go mon.Run(ctx)
	go srv.exportMetrics(ctx)

	errCh := make(chan error, 1)
	go func() {
		if !*live {
			fmt.Printf("listening on http://%s  (dashboard: http://%s/  metrics: http://%s/metrics)\n", *addr, *addr, *addr)
		}
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	var drv *driver
	if *drivePath != "" {
		reqs, err := loadRequests(*drivePath)
		if err != nil {
			return fmt.Errorf("load drive requests: %w", err)
		}
		drv = &driver{pool: p, requests: reqs, rate: *driveRate, timeout: *reqTimeout}
		go drv.run(ctx)
		if !*live {
			fmt.Printf("driving %d request shape(s) from %s at %.1f/s\n", len(reqs), *drivePath, *driveRate)
		}
	}

	if *live {
		view := &liveView{srv: srv, interval: *refresh, out: os.Stdout}
		go view.run(ctx)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		if *live {
			// Let the view's final frame land and its cursor be
			// restored before anything else writes to the terminal.
			time.Sleep(*refresh + 100*time.Millisecond)
		}
		fmt.Println("\nshutting down: draining requests, then destroying containers...")
	}

	srv.ready.Store(false)
	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	if err := p.Close(shutCtx); err != nil {
		return fmt.Errorf("pool shutdown: %w", err)
	}

	// Final evaluation before teardown: the last thing a container does
	// is often the most interesting thing it does.
	mon.Evaluate()
	final := mon.Score()
	finalSnap := mon.Aggregate()
	finalFindings := mon.Findings()
	mon.Close()

	if auditLog != nil {
		auditLog.Append(audit.Entry{
			Kind: audit.KindLifecycle,
			Lifecycle: &audit.Lifecycle{
				Event:  "session_end",
				Detail: fmt.Sprintf("posture=%s reason=%s requests=%d", final.Posture, final.PostureReason, final.Reliability.Requests),
			},
			Analysis: &audit.Analysis{Posture: string(final.Posture), Reason: final.PostureReason},
		})
		if err := auditLog.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "audit close:", err)
		}
		st := auditLog.Stats()
		fmt.Printf("audit chain head %s (%d entries", st.ChainHead, st.Written)
		if st.Dropped > 0 {
			fmt.Printf(", %d dropped and recorded as gaps", st.Dropped)
		}
		fmt.Println(")")
	}

	printFinalReport(srv, final, finalSnap, finalFindings)
	if drv != nil {
		fmt.Printf("  driver       %d requests sent, %d failed\n", drv.sent.Load(), drv.failed.Load())
	}
	fmt.Println("\nall containers destroyed; no sandbox state persists.")
	return nil
}

func newSessionID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return "sess_" + hex.EncodeToString(b)
}

func (s *server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST a JSON-RPC body", http.StatusMethodNotAllowed)
		return
	}
	if !s.ready.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	res, err := s.pool.Do(ctx, runtime.ExecRequest{
		RequestID: r.Header.Get("X-Request-Id"),
		Payload:   body,
		Timeout:   s.timeout,
	})
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, pool.ErrClosed) {
			status = http.StatusServiceUnavailable
		}
		// The container that served this request has already been
		// quarantined and replaced by the pool; the client just sees a
		// failed call.
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if n := len(res.Unsolicited); n > 0 {
		w.Header().Set("X-Warden-Unsolicited", fmt.Sprint(n))
	}
	w.Write(append(res.Payload, '\n'))
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_ = s.reg.WritePrometheus(w)
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	snap := struct {
		Target string           `json:"target"`
		Digest string           `json:"profile_digest"`
		Pool   int              `json:"pool_size"`
		Ready  bool             `json:"ready"`
		M      metrics.Snapshot `json:"metrics"`
	}{s.target, s.digest, s.poolN, s.ready.Load(), s.reg.Snapshot()}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
