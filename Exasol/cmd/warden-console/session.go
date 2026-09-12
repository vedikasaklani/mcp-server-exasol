package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/audit"
	"mcp-warden/sandbox/bridge"
	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/fetch"
	"mcp-warden/sandbox/metrics"
	"mcp-warden/sandbox/observe"
	"mcp-warden/sandbox/pool"
	"mcp-warden/sandbox/profile"
	"mcp-warden/sandbox/registry"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runsc"
	"mcp-warden/sandbox/sast"
)

// autoApprover is the approved_by written into a profile this console
// generated and approved on its own.
//
// §3.2 step 5 says never auto-promote a learned profile, because a server
// that misbehaved during profiling would have that behaviour baked into
// its own allowlist. The console does auto-promote — it has to, to be a
// one-command tool — so the one thing it must not do is let that fact get
// lost. The approver string says what actually happened, it is written
// into the profile on disk, it is printed before enforcement starts, and
// `profile` prints it again on demand.
const autoApprover = "operator:auto (warden-console, NOT human-reviewed — see docs/ARCHITECTURE.md §3.2 step 5)"

// session is one loaded MCP server: its source, its approved profile, its
// warm pool of confined containers, and everything watching them.
type session struct {
	source    string
	command   []string
	kind      string
	srcDir    string
	profile   *profile.CapabilityProfile
	profPath  string
	auditPath string
	// serverID is the trust/reputation platform's id for this source, once
	// resolved (see registry.Client.Resolve). Empty means storage is
	// disabled or the telemetry service was unreachable at load time.
	serverID string
	ref      string

	pool  *pool.Pool
	mon   *analyze.Monitor
	log   *audit.Log
	obs   *bridge.Observer
	reg   *metrics.Registry
	rt    *runsc.Runtime
	id    string
	poolN int

	// tools is the manifest captured during the warmup handshake, so
	// `tools` can answer without spending a container round trip.
	tools []toolInfo

	started time.Time
	cancel  context.CancelFunc
	dirs    []string // temp dirs to remove on close
}

// loadOptions is what `load` parsed out of the command line.
type loadOptions struct {
	poolSize     int
	networkMode  string
	learnTimeout time.Duration
	reqTimeout   time.Duration
	writePaths   []string
	analyze      string
	keepSource   bool
	// rollup collapses observed paths to this many leading directory
	// components in the generated profile. Zero means exact paths.
	//
	// A real Node server touches hundreds of files, and the profile grants
	// each one as its own bind mount. Rollup trades precision for a
	// smaller mount topology, and every trade it makes is a widening the
	// operator is told about rather than one that happens quietly.
	rollup int
	// sast runs Semgrep against the fetched source concurrently with
	// learning-mode profiling (sandbox/sast) and feeds the discovery/
	// reputation platform. It never blocks or gates confinement — see
	// docs/EXASOL_INTEGRATION.md.
	sast bool
}

func defaultLoadOptions() loadOptions {
	return loadOptions{
		poolSize:     2,
		networkMode:  "none",
		learnTimeout: 90 * time.Second,
		reqTimeout:   30 * time.Second,
		analyze:      "detect",
		sast:         true,
	}
}

// resolveSource turns whatever the operator typed into a runnable
// entrypoint. Four forms, distinguished by prefix rather than by
// guessing, because guessing wrong here means running the wrong program:
//
//	npm:<pkg> [args]   install a published npm package
//	cmd:<argv>         run an already-installed command verbatim
//	path:<dir>         detect and build a local directory
//	<git url>          clone, then detect and build
func resolveSource(ctx context.Context, spec string, args []string) (*fetch.Entrypoint, string, error) {
	ep, dir, err := resolveSourceKind(ctx, spec, args)
	if err != nil {
		return nil, "", err
	}
	// Resolve the interpreter against the host's PATH before the command
	// ever reaches a container. The guest's PATH is /usr/bin:/bin and
	// nothing else, so a bare "node" — which is what an npm package's bin
	// entry amounts to — is not findable inside the sandbox even though it
	// runs fine on the host. The profile also has to pin the digest of the
	// executable that will actually run, and it cannot hash a name.
	if len(ep.Command) > 0 && !filepath.IsAbs(ep.Command[0]) {
		resolved, lookErr := exec.LookPath(ep.Command[0])
		if lookErr != nil {
			return nil, "", fmt.Errorf("cannot find %q on PATH: %w", ep.Command[0], lookErr)
		}
		ep.Command[0] = resolved
	}
	return ep, dir, nil
}

func resolveSourceKind(ctx context.Context, spec string, args []string) (*fetch.Entrypoint, string, error) {
	switch {
	case strings.HasPrefix(spec, "npm:"):
		ep, dir, err := fetch.FromNPM(ctx, strings.TrimPrefix(spec, "npm:"), args)
		return ep, dir, err

	case strings.HasPrefix(spec, "cmd:"):
		argv := append(strings.Fields(strings.TrimPrefix(spec, "cmd:")), args...)
		if len(argv) == 0 {
			return nil, "", fmt.Errorf("cmd: needs a command to run")
		}
		return &fetch.Entrypoint{
			Command: argv,
			Kind:    "command",
			Notes:   []string{"running an operator-supplied command verbatim; nothing was fetched or built"},
		}, "", nil

	case strings.HasPrefix(spec, "path:"):
		dir := strings.TrimPrefix(spec, "path:")
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, "", err
		}
		ep, err := fetch.Detect(ctx, abs, fetch.Options{})
		// A local path is the operator's own tree: never delete it.
		return ep, "", err

	default:
		dir, err := fetch.Clone(ctx, spec, "")
		if err != nil {
			return nil, "", err
		}
		ep, err := fetch.Detect(ctx, dir, fetch.Options{})
		if err != nil {
			os.RemoveAll(dir)
			return nil, "", err
		}
		return ep, dir, nil
	}
}

// load runs the whole pipeline: fetch, profile under learning mode,
// auto-approve, compile, and warm a pool of confined containers.
func (c *console) load(ctx context.Context, spec string, args []string, opts loadOptions) (*session, error) {
	step("resolving %s", spec)
	warn("fetch and build run UNCONFINED on this host — npm/pip/go execute the project's own install scripts. Only the resolved server process is sandboxed.")

	ep, srcDir, err := resolveSource(ctx, spec, args)
	if err != nil {
		return nil, err
	}
	ok(" %s entrypoint: %s", ep.Kind, strings.Join(ep.Command, " "))
	for _, n := range ep.Notes {
		detail("%s", n)
	}

	s := &session{
		source:  spec,
		command: ep.Command,
		kind:    ep.Kind,
		srcDir:  srcDir,
		id:      newSessionID(),
		poolN:   opts.poolSize,
		started: time.Now(),
	}
	if srcDir != "" && !opts.keepSource {
		s.dirs = append(s.dirs, srcDir)
	}
	cleanupOnFailure := func() {
		for _, d := range s.dirs {
			os.RemoveAll(d)
		}
	}
	s.ref = sourceRef(spec, ep)

	// ---- SAST (concurrent with learning mode, never blocking) ----------
	//
	// Launched here, before learning mode starts, so Semgrep's few seconds
	// overlap with profiling/confinement instead of adding to load's total
	// time. It resolves its own server_id independently rather than
	// reading s.serverID (set further down, after this goroutine is
	// already running) - two goroutines racing on one field is exactly the
	// kind of bug this avoids by construction. resolve_server is a
	// deterministic get-or-create, so calling it twice for the same source
	// is harmless.
	// ep.Cwd is the specific package/project directory: for npm, the
	// installed package under node_modules rather than the temp root
	// holding its whole dependency tree, and for a path: source, the
	// operator's own directory. Gating on srcDir instead would skip SAST
	// entirely for path: sources, since srcDir doubles as "the temp dir to
	// delete afterwards" and is deliberately empty for a tree warden does
	// not own. Only cmd: sources have no scannable directory at all.
	scanDir := ep.Cwd
	if scanDir == "" {
		scanDir = srcDir
	}
	if opts.sast && scanDir != "" && c.storage.Enabled() {
		c.sastWG.Add(1)
		go func() {
			defer c.sastWG.Done()
			c.runSAST(spec, ep.Kind, scanDir, s.ref)
		}()
	}

	// ---- learning mode -------------------------------------------------
	step("profiling under learning mode")
	warn("LEARNING MODE IS AN UNCONFINED EXECUTION (§6.4): no seccomp filter, no path confinement, network=%s.", opts.networkMode)

	learnCtx, cancel := context.WithTimeout(ctx, opts.learnTimeout)
	report, obsErr := observe.Run(learnCtx, observe.Target{
		Command:     ep.Command,
		Cwd:         ep.Cwd,
		NetworkMode: opts.networkMode,
		Requests: [][]byte{
			observe.DefaultMCPInitializeRequest(),
			[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
			[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`),
		},
	}, observe.RunOptions{
		Timeout:        opts.learnTimeout,
		RequestTimeout: opts.reqTimeout,
		GlobalFlags:    runscGlobalFlags(),
	})
	cancel()
	if obsErr != nil && report == nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("learning-mode run: %w", obsErr)
	}
	if len(report.Syscalls) == 0 {
		cleanupOnFailure()
		detail := report.ExitErr
		if detail == "" {
			detail = "no exit error recorded either"
		}
		return nil, fmt.Errorf("learning-mode run saw no syscalls — the server did not start: %s", detail)
	}
	ok(" observed %d syscalls, %d paths in %v", len(report.Syscalls), len(report.Paths), report.Duration.Round(time.Millisecond))

	// ---- profile -------------------------------------------------------
	cand, err := observe.GenerateProfile(report, observe.ProfileOptions{
		ToolName:    toolNameOf(spec),
		WritePaths:  opts.writePaths,
		RollupDepth: opts.rollup,
	})
	if err != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("generate profile: %w", err)
	}
	cand.Profile.ApprovedBy = autoApprover
	s.profile = cand.Profile

	profDir, err := os.MkdirTemp("", "warden-console-profile-")
	if err != nil {
		cleanupOnFailure()
		return nil, err
	}
	s.dirs = append(s.dirs, profDir)
	s.profPath = filepath.Join(profDir, "profile.json")
	data, err := json.MarshalIndent(cand.Profile, "", "  ")
	if err != nil {
		cleanupOnFailure()
		return nil, err
	}
	if err := os.WriteFile(s.profPath, append(data, '\n'), 0o644); err != nil {
		cleanupOnFailure()
		return nil, err
	}

	tool := cand.Profile.Tools[0]
	ok(" profile: %d syscalls, %d read paths, %d write paths", len(tool.Syscalls), len(tool.Filesystem.Read), len(tool.Filesystem.Write))
	warn("auto-approved as %s", autoApprover)
	if len(cand.BroadGrants) > 0 {
		warn("this profile grants whole system trees: %s — far broader than a reviewed profile would be", strings.Join(cand.BroadGrants, ", "))
	}
	if len(cand.Widenings) > 0 {
		detail("rollup depth %d granted broader access than was observed in %d place(s); `profile` lists the grants", opts.rollup, len(cand.Widenings))
	}

	policy, err := compile.Session(cand.Profile, compile.Options{})
	if err != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	// ---- confined runtime ----------------------------------------------
	step("warming %d confined container(s)", opts.poolSize)

	bundleRoot, err := os.MkdirTemp("", "warden-console-bundle-")
	if err != nil {
		cleanupOnFailure()
		return nil, err
	}
	s.dirs = append(s.dirs, bundleRoot)
	rootfs, err := os.MkdirTemp("", "warden-console-rootfs-")
	if err != nil {
		cleanupOnFailure()
		return nil, err
	}
	s.dirs = append(s.dirs, rootfs)

	// Own the trace root explicitly rather than letting it default beside
	// the bundle: when a container fails to boot, gVisor's own reason is
	// in that log and nowhere else, and a path this process chose is a
	// path it can go read afterwards.
	traceRoot, err := os.MkdirTemp("", "warden-console-trace-")
	if err != nil {
		cleanupOnFailure()
		return nil, err
	}
	s.dirs = append(s.dirs, traceRoot)

	rt := &runsc.Runtime{
		BundleRoot:  bundleRoot,
		TraceRoot:   traceRoot,
		GlobalFlags: runscGlobalFlags(),
		Rootfs: runsc.BundleConfig{
			RootfsPath: rootfs,
			Args:       ep.Command,
			Cwd:        ep.Cwd,
			Env: []string{
				"PATH=/usr/bin:/bin",
				"HOME=/tmp/scratch",
				"TMPDIR=/tmp/scratch",
			},
		},
		ProbeBinaryPath: c.probeBin,
		Limits:          runsc.DefaultLimits(),
	}
	switch opts.analyze {
	case "off":
	case "detect":
		rt.Trace = true
		rt.TraceSyscalls = runsc.DetectionSyscalls
	case "full":
		rt.Trace = true
	default:
		cleanupOnFailure()
		return nil, fmt.Errorf("analyze must be off, detect or full (got %q)", opts.analyze)
	}
	s.rt = rt

	sup := runtime.NewEnforcingSupervisor(rt)
	s.reg = metrics.NewRegistry()

	// The audit chain outlives the session deliberately. Everything else
	// here is sandbox state and must not persist (§6.2: "container
	// destroyed, tmpfs discarded, no state persists"), but §7.1's whole
	// point is a tamper-evident record you can verify afterwards — writing
	// it into a directory that `stop` deletes would make the chain
	// unverifiable the moment it became worth verifying.
	auditDir := filepath.Join(os.Getenv("HOME"), ".warden", "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		auditDir = profDir // fall back rather than refusing to run
	}
	s.auditPath = filepath.Join(auditDir, s.id+".jsonl")
	s.log, err = audit.Open(audit.Config{
		Path:      s.auditPath,
		SessionID: s.id,
		ServerID:  toolNameOf(spec),
		// Enforcing, never learning: the learning pass above is over by
		// the time this chain opens, and it wrote nothing into it.
		ImageDigest:  cand.Profile.ImageDigest,
		LearningMode: sup.Mode() != runtime.ModeEnforcing,
	})
	if err != nil {
		cleanupOnFailure()
		return nil, fmt.Errorf("open audit chain: %w", err)
	}

	baseline := analyze.BaselineFromProfile(cand.Profile)
	var obs *bridge.Observer
	s.mon = analyze.NewMonitor(analyze.MonitorConfig{
		Baseline:      baseline,
		Locate:        rt.TraceDir,
		EvaluateEvery: 2 * time.Second,
		OnFinding:     func(id string, f analyze.Finding) { obs.OnFinding(id, f) },
	})
	obs = bridge.New(s.mon, s.log)
	s.obs = obs
	s.mon.SetEntrypoint(analyze.MeasureEntrypoint(ep.Command[0]))

	if c.storage.Enabled() {
		s.serverID = c.storage.Resolve(ctx, spec, ep.Kind, s.ref)
		if s.serverID != "" {
			obs.Storage = c.storage
			obs.ServerID = s.serverID
			obs.SessionID = s.id
			obs.Networks = baseline.Network
			detail("registered with the trust/reputation platform: server_id=%s", s.serverID)
		} else {
			detail("telemetry service unreachable — discovery/reputation/audit trail won't be recorded for this session (`status` shows connectivity)")
		}
	}

	s.log.Append(audit.Entry{
		Kind: audit.KindLifecycle,
		Lifecycle: &audit.Lifecycle{
			Event:  "session_start",
			Detail: fmt.Sprintf("source=%s target=%s approver=auto", spec, strings.Join(ep.Command, " ")),
		},
	})

	p, err := pool.New(ctx, sup, policy, pool.Config{
		Size:           opts.poolSize,
		AcquireTimeout: 10 * time.Second,
		Observer:       obs,
		Warmup:         bridge.Handshake(opts.reqTimeout),
		OnWarmupResponse: func(containerID string, req runtime.ExecRequest, res runtime.ExecResult) {
			// tools/list is where the manifest is pinned (§4.2 step 3).
			s.mon.ObserveResponse(containerID, res.Payload)
			if req.RequestID == "warmup:tools-list" {
				s.rememberTools(res.Payload)
				if s.serverID != "" {
					c.storage.PostToolDiscovery(s.serverID, toRegistryTools(s.toolList()), "observed")
				}
			}
		},
	}, s.reg)
	if err != nil {
		s.log.Close()
		// Do NOT clean up here. A container that would not boot leaves its
		// reason in gVisor's debug log and its exact mount topology in
		// config.json; deleting both and reporting only runsc's frontend
		// message ("cannot read client sync file") is how this failure
		// stays undiagnosable across runs.
		diagnoseBootFailure(traceRoot, bundleRoot, len(tool.Filesystem.Read)+len(tool.Filesystem.Write))
		return nil, fmt.Errorf("warm pool (a sandbox that cannot be verified must not serve traffic): %w", err)
	}
	s.pool = p

	monCtx, monCancel := context.WithCancel(context.Background())
	s.cancel = monCancel
	go s.mon.Run(monCtx)

	if filterDropped, tracingDropped := rt.TraceDegraded(); tracingDropped {
		warn("this runsc would not start a traced container: behavioural analysis is OFF (confinement is still enforced)")
	} else if filterDropped {
		detail("runsc rejected the syscall trace filter; tracing every syscall instead (higher overhead, same coverage)")
	}
	return s, nil
}

// close tears the session down: drain, destroy containers, close the
// chain, remove temp state. Nothing about a session survives it.
func (s *session) close(ctx context.Context) {
	if s.cancel != nil {
		s.cancel()
	}
	if s.pool != nil {
		if err := s.pool.Close(ctx); err != nil {
			fail("pool shutdown: %v", err)
		}
	}
	if s.mon != nil {
		s.mon.Evaluate()
		final := s.mon.Score()
		// Written before the monitor and chain are closed, so the summary
		// reflects the whole session including whatever the final
		// Evaluate() just surfaced.
		if s.obs != nil {
			var entries int64
			if s.log != nil {
				entries = s.log.Stats().Written
			}
			confinement := "enforcing"
			if rootless() {
				confinement = "rootless-no-cgroups"
			}
			if err := s.obs.PostSession(ctx, s.started, confinement, entries); err != nil {
				detail("session summary not recorded: %v", err)
			}
		}
		if s.log != nil {
			s.log.Append(audit.Entry{
				Kind: audit.KindLifecycle,
				Lifecycle: &audit.Lifecycle{
					Event:  "session_end",
					Detail: fmt.Sprintf("posture=%s requests=%d", final.Posture, final.Reliability.Requests),
				},
				Analysis: &audit.Analysis{Posture: string(final.Posture), Reason: final.PostureReason},
			})
		}
		s.mon.Close()
	}
	if s.log != nil {
		if err := s.log.Close(); err != nil {
			fail("audit close: %v", err)
		}
	}
	for _, d := range s.dirs {
		os.RemoveAll(d)
	}
}

// runscGlobalFlags returns the runsc invocation flags this host needs.
//
// As root, none: the fully confined configuration in §6.1 is available,
// cgroup limits included. Unprivileged, gVisor cannot configure cgroups
// (it fails at /sys/fs/cgroup/cgroup.subtree_control) and refuses its
// default network mode, so it needs telling to skip both.
//
// Running unprivileged keeps the two controls that carry the security
// argument — the compiled seccomp filter and a mount table containing
// only declared paths, both still proven per container by the canary —
// and loses §6.1.5's resource limits. That is a real reduction and
// `status` says so; it is not the same thing as running unconfined.
func runscGlobalFlags() []string {
	if os.Geteuid() == 0 {
		return nil
	}
	return []string{"--rootless", "--ignore-cgroups", "--network=none"}
}

// rootless reports whether this process must use the unprivileged runsc
// configuration.
func rootless() bool { return os.Geteuid() != 0 }

func newSessionID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return "sess_" + hex.EncodeToString(b)
}

// toolNameOf derives a short name for the loaded server from whatever
// source spec produced it.
func toolNameOf(spec string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(spec, "/"), ".git")
	for _, p := range []string{"npm:", "cmd:", "path:"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexAny(s, " \t"); i > 0 {
		s = s[:i]
	}
	parts := strings.Split(s, "/")
	name := parts[len(parts)-1]
	if name == "" {
		return "server"
	}
	return name
}

// sourceRef identifies the exact version of spec that was loaded, so a
// rescan job can tell whether the source has moved on since. An npm
// package's installed version comes from its own package.json; anything
// else fetched via git reports its checked-out commit. path:/cmd: sources
// have no meaningful ref - "" disables rescan tracking for them.
func sourceRef(spec string, ep *fetch.Entrypoint) string {
	if strings.HasPrefix(spec, "npm:") && ep.Cwd != "" {
		data, err := os.ReadFile(filepath.Join(ep.Cwd, "package.json"))
		if err != nil {
			return ""
		}
		var pkg struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			return pkg.Version
		}
		return ""
	}
	if ep.Cwd != "" {
		out, err := exec.Command("git", "-C", ep.Cwd, "rev-parse", "HEAD").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

// toRegistryTools adapts the console's own toolInfo (captured from the
// live tools/list response) to what the telemetry API expects.
func toRegistryTools(tools []toolInfo) []registry.ToolInfo {
	out := make([]registry.ToolInfo, len(tools))
	for i, t := range tools {
		var schema any
		if len(t.InputSchema) > 0 {
			_ = json.Unmarshal(t.InputSchema, &schema)
		}
		out[i] = registry.ToolInfo{Name: t.Name, Description: t.Description, ParameterSchema: schema}
	}
	return out
}

// cmdRescan re-runs SAST against the loaded session's source on demand,
// independent of any background schedule. Useful right after `load` if
// the async scan hasn't printed its result yet, or to re-check after
// editing a path: source in place.
func (c *console) cmdRescan() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	if c.sess.srcDir == "" {
		fail("this source has no fetched tree to scan (path:/cmd: sources scan in place only if given as path:)")
		return
	}
	if !c.storage.Enabled() {
		fail("storage is off — `set storage on` first")
		return
	}
	step("re-scanning %s", c.sess.source)
	c.runSAST(c.sess.source, c.sess.kind, c.sess.srcDir, c.sess.ref)
}

// runSAST scans srcDir with Semgrep and, if the telemetry service is
// reachable, records the findings and declared tools against source's
// server_id. It runs as its own goroutine from load(), overlapping with
// learning-mode profiling rather than adding to it, and touches no session
// state - see the comment at its call site for why.
func (c *console) runSAST(source, kind, srcDir, ref string) {
	rep, err := sast.Run(context.Background(), srcDir, sast.Options{
		PythonRepo: filepath.Join(c.repoRoot, "mcp-server-exasol"),
	})
	if err != nil {
		warn("SAST scan failed: %v", err)
		return
	}
	sevCounts := map[string]int{}
	findings := make([]registry.Finding, len(rep.Findings))
	for i, f := range rep.Findings {
		findings[i] = registry.Finding{
			Analyzer: f.Analyzer, Severity: f.Severity, RuleID: f.RuleID,
			File: f.File, Line: f.Line, Message: f.Message,
		}
		sevCounts[strings.ToUpper(f.Severity)]++
	}
	tools := make([]registry.ToolInfo, len(rep.ToolDeclarations))
	for i, t := range rep.ToolDeclarations {
		tools[i] = registry.ToolInfo{Name: t.Name, Description: t.Description, ParameterSchema: t.ParameterSchema}
	}

	serverID := c.storage.Resolve(context.Background(), source, kind, ref)
	if serverID != "" {
		c.storage.PostSASTFindings(serverID, findings, tools, ref)
	}

	if rep.Error != "" {
		detail("SAST: %d finding(s), %d declared tool(s) — %s", len(rep.Findings), len(rep.ToolDeclarations), rep.Error)
	} else {
		ok(" SAST: %d finding(s) (crit %d, high %d, med %d, low %d), %d declared tool(s)",
			len(rep.Findings), sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"], len(rep.ToolDeclarations))
	}
}
