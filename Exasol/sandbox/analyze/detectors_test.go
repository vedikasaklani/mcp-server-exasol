package analyze

import (
	"fmt"
	"testing"
	"time"

	"mcp-warden/sandbox/observe"
	"mcp-warden/sandbox/profile"
)

// benignProfile approximates a real filesystem MCP server's approved
// profile: a Node entrypoint, its module tree, and one data directory.
func benignProfile() *profile.CapabilityProfile {
	return &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    "sha256:abc",
		GeneratedBy:    "learning_mode",
		ApprovedBy:     "operator:neal",
		Tools: []profile.Tool{{
			Name:     "read_file",
			Effects:  []profile.Effect{profile.EffectRead},
			Syscalls: []string{"read", "write", "openat", "close", "newfstatat", "mmap", "futex", "epoll_wait"},
			Filesystem: profile.FilesystemAccess{
				Read:  []string{"/usr/lib/node_modules", "/srv/data", "/usr/bin/node", "/lib64"},
				Write: []string{"/tmp/scratch"},
			},
			MaxDurationMS: 5000,
		}},
	}
}

// runBenign drives an engine through a session that looks like a healthy
// server: module resolution (which probes paths that do not exist), reads
// inside the declared data directory, and responses on stdout.
func runBenign(t *testing.T, e *Engine, c *clock, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r%d", i)
		e.BeginRequest(id, "read_file", []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/data/f%d.txt"}}}`, i, i)))
		c.advance(time.Millisecond)
		// Module resolution probes several paths that are not there.
		for j := 0; j < 3; j++ {
			e.Ingest(evErr(c.now(), 1, "newfstatat",
				fmt.Sprintf(`AT_FDCWD /, 0x1 /usr/lib/node_modules/pkg/v%d/index.js, 0x2, 0x0`, j), 2, "no such file or directory"))
		}
		e.Ingest(ev(c.now(), 1, "openat", fmt.Sprintf(`AT_FDCWD /, 0x1 /srv/data/f%d.txt, O_RDONLY|0x0, 0o0`, i), 7))
		e.Ingest(ev(c.now(), 1, "read", `0x7, 0x100, 0x1000`, 512))
		e.Ingest(ev(c.now(), 1, "close", `0x7`, 0))
		e.Ingest(ev(c.now(), 1, "write", `0x1, 0x200, 0x200`, 540))
		c.advance(2 * time.Millisecond)
		e.EndRequest(id, Outcome{ResponseBytes: 540, Latency: 3 * time.Millisecond, ToolName: "read_file"})
		c.advance(5 * time.Millisecond)
	}
}

// securityFindings returns findings that assert something went wrong.
// Info-severity notes are excluded: they describe configuration ("this
// profile could pin its entrypoint"), not behaviour, and cannot move a
// tier. Anything at low or above on a healthy session is a false
// positive.
func securityFindings(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if securityFamilies[f.Family] && f.Severity != SeverityInfo {
			out = append(out, f)
		}
	}
	return out
}

func TestDetectors_BenignSessionProducesNoSecurityFindings(t *testing.T) {
	// The single most important test in this package. A detector set that
	// fires on healthy traffic gets switched off, and a switched-off
	// detector catches nothing.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b)
	e.SetPipelineStats(mockTailStats(10000, 0), true)
	e.SetEntrypoint(EntrypointIdentity{Path: "/usr/bin/node", SHA256: "sha256:node"})

	runBenign(t, e, c, 40)
	found := securityFindings(e.Evaluate())
	if len(found) != 0 {
		for _, f := range found {
			t.Errorf("false positive: %s", f)
		}
		t.Fatalf("%d security finding(s) on a benign session", len(found))
	}
	if got := e.Score().Posture; got != TierTrusted {
		t.Fatalf("posture = %q, want %q", got, TierTrusted)
	}
}

func TestDetectors_PathDriftSeparatesReadsWritesAndProbes(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, PathDrift{})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /var/lib/other/data.db, O_RDONLY|0x0, 0o0`, 5))
	e.Ingest(ev(c.now(), 1, "read", `0x5, 0x100, 0x1000`, 900))
	e.Ingest(ev(c.now(), 1, "unlinkat", `AT_FDCWD /, 0x1 /etc/motd, 0x0`, 0))
	e.Ingest(evErr(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /root/.bashrc, O_RDONLY|0x0, 0o0`, 2, "no such file or directory"))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{Latency: time.Millisecond})

	fs := e.Evaluate()
	for _, key := range []string{"path-drift:write", "path-drift:read", "path-drift:probe"} {
		if !hasKey(fs, key) {
			t.Errorf("missing %s in %v", key, keys(fs))
		}
	}
	if sev := severityOf(fs, "path-drift:write"); sev != SeverityCritical {
		t.Errorf("undeclared write severity = %q, want critical", sev)
	}
	if sev := severityOf(fs, "path-drift:probe"); sev != SeverityLow {
		t.Errorf("a handful of failed probes should be low, got %q", sev)
	}
}

func TestDetectors_SyscallDriftDistinguishesRefusedFromSucceeded(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, SyscallDrift{})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	// Refused: this is confinement working.
	e.Ingest(evErr(c.now(), 1, "ptrace", `0x10, 0x1, 0x0, 0x0`, 1, "operation not permitted"))
	// Succeeded: this is confinement NOT working.
	e.Ingest(ev(c.now(), 1, "unshare", `0x20000000`, 0))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{Latency: time.Millisecond})

	fs := e.Evaluate()
	if severityOf(fs, "syscall-drift:refused") != SeverityHigh {
		t.Errorf("a refused undeclared syscall should be high, got %q", severityOf(fs, "syscall-drift:refused"))
	}
	if severityOf(fs, "syscall-drift:succeeded") != SeverityCritical {
		t.Errorf("an undeclared syscall that SUCCEEDED means the enforced filter does not match the profile — that must be critical, got %q",
			severityOf(fs, "syscall-drift:succeeded"))
	}
}

func TestDetectors_ReadThenEgressCatchesTheSequenceNoSingleCallViolates(t *testing.T) {
	// Each call here is individually permissible. The order is the
	// attack, and it is the case §5.3 says per-call authorization
	// structurally cannot see.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, ReadThenEgress{})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/.aws/credentials, O_RDONLY|0x0, 0o0`, 4))
	e.Ingest(ev(c.now(), 1, "read", `0x4, 0x100, 0x1000`, 300))
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "socket", `0x2, 0x1, 0x0`, 9))
	e.Ingest(ev(c.now(), 1, "connect", `0x9 socket:[2], 0x7f {Family: AF_INET, Addr: 198.51.100.7, Port: 443}, 0x10`, 0))
	e.Ingest(ev(c.now(), 1, "sendto", `0x9, 0x100, 0x12c, 0x0, 0x0, 0x0`, 300))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 40, Latency: 3 * time.Millisecond})

	fs := e.Evaluate()
	if !hasDetector(fs, "read-then-egress") {
		t.Fatalf("credential read followed by egress must be detected: %v", keys(fs))
	}
	f := findByDetector(fs, "read-then-egress")
	if f.Severity != SeverityCritical || f.Confidence != ConfidenceDeterministic {
		t.Errorf("got %s/%s, want critical/deterministic — every element of this claim is an observed fact", f.Severity, f.Confidence)
	}
	if e.Score().Posture != TierQuarantine {
		t.Errorf("posture = %q, want quarantine", e.Score().Posture)
	}
}

func TestDetectors_EgressWithoutSensitiveReadIsStillReportedByVolume(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, EgressVolume{})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "socket", `0x2, 0x1, 0x0`, 9))
	e.Ingest(ev(c.now(), 1, "write", `0x9, 0x100, 0x100000`, 1<<20))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 200, Latency: time.Millisecond})

	if !hasDetector(e.Evaluate(), "egress-volume") {
		t.Fatalf("a megabyte out a socket against a 200-byte response must be reported")
	}
}

func TestDetectors_IdleEgressIsCriticalBecauseNoCallerAskedForIt(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, EgressVolume{})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 100, Latency: time.Millisecond})

	c.advance(time.Second)
	e.Ingest(ev(c.now(), 1, "socket", `0x2, 0x1, 0x0`, 9))
	e.Ingest(ev(c.now(), 1, "write", `0x9, 0x100, 0x8000`, 32768))

	f := findByDetector(e.Evaluate(), "egress-volume")
	if f.Severity != SeverityCritical {
		t.Fatalf("egress with no request in flight has no caller to explain it; severity = %q", f.Severity)
	}
}

func TestDetectors_EnumerationNeedsARateNotACount(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, Enumeration{})

	// A healthy Node startup misses plenty of paths while still finding
	// most of what it opens.
	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	for i := 0; i < 100; i++ {
		e.Ingest(evErr(c.now(), 1, "newfstatat", fmt.Sprintf(`AT_FDCWD /, 0x1 /m/%d, 0x0, 0x0`, i), 2, "no such file or directory"))
	}
	for i := 0; i < 300; i++ {
		e.Ingest(ev(c.now(), 1, "openat", fmt.Sprintf(`AT_FDCWD /, 0x1 /srv/data/%d, O_RDONLY|0x0, 0o0`, i), 5))
	}
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{Latency: time.Millisecond})
	if hasDetector(e.Evaluate(), "enumeration") {
		t.Fatalf("25%% misses is normal module resolution and must not fire")
	}

	// Sweeping a directory tree that mostly is not there is not.
	e2, c2 := newTestEngine(t, b, Enumeration{})
	e2.BeginRequest("r1", "read_file", nil)
	c2.advance(time.Millisecond)
	for i := 0; i < 400; i++ {
		e2.Ingest(evErr(c2.now(), 1, "openat", fmt.Sprintf(`AT_FDCWD /, 0x1 /home/u%d/.ssh/id_rsa, O_RDONLY|0x0, 0o0`, i), 2, "no such file or directory"))
	}
	c2.advance(time.Millisecond)
	e2.EndRequest("r1", Outcome{Latency: time.Millisecond})
	if !hasDetector(e2.Evaluate(), "enumeration") {
		t.Fatalf("a sweep that finds almost nothing is reconnaissance and must fire")
	}
}

func TestDetectors_SupplyChainCatchesExecModuleAndNativeDrift(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, UnexpectedExec{}, ModuleDrift{}, NativeCodeLoad{}, WriteThenExec{})
	e.SetEntrypoint(EntrypointIdentity{Path: "/usr/bin/node", SHA256: "sha256:node"})

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	// A dependency that was not there at approval time.
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /opt/app/node_modules/evil/index.js, O_RDONLY|0x0, 0o0`, 5))
	e.Ingest(ev(c.now(), 1, "read", `0x5, 0x1, 0x400`, 900))
	// Native code from a path the server can write.
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /tmp/scratch/payload.so, O_RDONLY|0x0, 0o0`, 6))
	e.Ingest(ev(c.now(), 1, "read", `0x6, 0x1, 0x400`, 900))
	// A shell.
	e.Ingest(ev(c.now(), 1, "execve", `0x1 /bin/sh, 0x2, 0x3`, 0))
	// And something it wrote, then ran.
	e.Ingest(ev(c.now(), 1, "execve", `0x1 /tmp/scratch/dropper, 0x2, 0x3`, 0))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{Latency: time.Millisecond})

	fs := e.Evaluate()
	for _, name := range []string{"unexpected-exec", "module-drift", "native-code-load", "write-then-exec"} {
		if !hasDetector(fs, name) {
			t.Errorf("%s did not fire; got %v", name, keys(fs))
		}
	}
	if severityOf(fs, "native-code-load:writable") != SeverityCritical {
		t.Errorf("a library loaded from a writable path is unreviewable code and must be critical")
	}
}

func TestDetectors_EntrypointDriftCatchesASwappedInterpreter(t *testing.T) {
	p := benignProfile()
	p.Entrypoint = &profile.EntrypointAttestation{
		Path: "/usr/bin/node", SHA256: "sha256:good",
		Interpreter: "/lib64/ld-linux-x86-64.so.2", InterpreterSHA256: "sha256:goodld",
	}
	b := BaselineFromProfile(p)
	e, _ := newTestEngine(t, b, EntrypointDrift{})
	e.SetEntrypoint(EntrypointIdentity{
		Path: "/usr/bin/node", SHA256: "sha256:good",
		Interpreter: "/lib64/ld-linux-x86-64.so.2", InterpreterSHA256: "sha256:TAMPERED",
	})

	fs := e.Evaluate()
	if !hasKey(fs, "entrypoint-drift:interpreter") {
		t.Fatalf("a swapped ELF interpreter appears in no syscall trace; digest pinning is the only thing that catches it: %v", keys(fs))
	}
	if hasKey(fs, "entrypoint-drift:binary") {
		t.Errorf("the binary itself matched and must not be reported as drifted")
	}
}

func TestDetectors_EntrypointMatchingPinIsSilent(t *testing.T) {
	p := benignProfile()
	p.Entrypoint = &profile.EntrypointAttestation{Path: "/usr/bin/node", SHA256: "sha256:good"}
	e, _ := newTestEngine(t, BaselineFromProfile(p), EntrypointDrift{})
	e.SetEntrypoint(EntrypointIdentity{Path: "/usr/bin/node", SHA256: "sha256:good"})
	if fs := e.Evaluate(); len(fs) != 0 {
		t.Fatalf("a matching digest must produce nothing, got %v", keys(fs))
	}
}

func TestDetectors_BeaconingNeedsRegularityNotJustActivity(t *testing.T) {
	b := BaselineFromProfile(benignProfile())

	// Irregular background work: real event-driven servers look like this.
	irregular, c1 := newTestEngine(t, b, Beaconing{})
	gaps := []time.Duration{2 * time.Second, 17 * time.Second, 3 * time.Second, 40 * time.Second, 5 * time.Second, 21 * time.Second, 9 * time.Second}
	for _, g := range gaps {
		c1.advance(g)
		irregular.Ingest(ev(c1.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/x, O_RDONLY|0x0, 0o0`, 3))
	}
	if hasDetector(irregular.Evaluate(), "beaconing") {
		t.Errorf("irregular background work must not be reported as a beacon")
	}

	// A poll on a fixed interval.
	regular, c2 := newTestEngine(t, b, Beaconing{})
	for i := 0; i < 10; i++ {
		c2.advance(30 * time.Second)
		regular.Ingest(ev(c2.now(), 1, "socket", `0x2, 0x1, 0x0`, 8))
		regular.Ingest(ev(c2.now(), 1, "connect", `0x8, 0x7f {Family: AF_INET, Addr: 198.51.100.7, Port: 443}, 0x10`, 0))
		regular.Ingest(ev(c2.now(), 1, "sendto", `0x8, 0x1, 0x40, 0x0, 0x0, 0x0`, 64))
	}
	f := findByDetector(regular.Evaluate(), "beaconing")
	if f.Detector == "" {
		t.Fatalf("a fixed-interval poll with network egress is the shape of C2 traffic and must be reported")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("periodic idle egress severity = %q, want critical", f.Severity)
	}
	if f.Confidence != ConfidenceStatistical {
		t.Errorf("periodicity is an inference and must be labelled statistical, got %q", f.Confidence)
	}
}

func TestDetectors_ArgumentAccessMismatch(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, ArgumentAccessMismatch{})

	e.BeginRequest("r1", "read_file", []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/data/report.csv"}}}`))
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/report.csv, O_RDONLY|0x0, 0o0`, 5))
	e.Ingest(ev(c.now(), 1, "read", `0x5, 0x1, 0x400`, 900))
	// Nothing in the request named this.
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /home/neal/.ssh/id_ed25519, O_RDONLY|0x0, 0o0`, 6))
	e.Ingest(ev(c.now(), 1, "read", `0x6, 0x1, 0x400`, 400))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 900, Latency: time.Millisecond})

	f := findByDetector(e.Evaluate(), "argument-access-mismatch")
	if f.Detector == "" {
		t.Fatalf("files unrelated to the call's arguments must be reported")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("an unrelated *credential* path should escalate to critical, got %q", f.Severity)
	}
}

func TestDetectors_ArgumentAccessMismatchIgnoresRuntimeInternals(t *testing.T) {
	// Module loads and library mapping are the runtime's business, not
	// the request's. Counting them would make every call a mismatch.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, ArgumentAccessMismatch{})

	e.BeginRequest("r1", "read_file", []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/data/report.csv"}}}`))
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/report.csv, O_RDONLY|0x0, 0o0`, 5))
	e.Ingest(ev(c.now(), 1, "read", `0x5, 0x1, 0x400`, 900))
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /usr/lib/node_modules/lodash/index.js, O_RDONLY|0x0, 0o0`, 6))
	e.Ingest(ev(c.now(), 1, "read", `0x6, 0x1, 0x400`, 4000))
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /lib64/libc.so.6, O_RDONLY|0x0, 0o0`, 7))
	e.Ingest(ev(c.now(), 1, "read", `0x7, 0x1, 0x400`, 8000))
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 900, Latency: time.Millisecond})

	if hasDetector(e.Evaluate(), "argument-access-mismatch") {
		t.Fatalf("module and library loads must not read as unrelated access")
	}
}

func TestDetectors_PipelineHealthMakesSilenceUnambiguous(t *testing.T) {
	b := BaselineFromProfile(benignProfile())

	off, _ := newTestEngine(t, b, PipelineHealth{})
	off.SetPipelineStats(mockTailStats(0, 0), false)
	if !hasKey(off.Evaluate(), "pipeline-health:disabled") {
		t.Errorf("with tracing off, the dashboard must say so rather than showing a clean board")
	}

	dropping, c := newTestEngine(t, b, PipelineHealth{})
	dropping.SetPipelineStats(mockTailStats(0, 0), true)
	dropping.BeginRequest("r1", "t", nil)
	c.advance(time.Millisecond)
	for i := 0; i < 1000; i++ {
		dropping.Ingest(ev(c.now(), 1, "getpid", ``, 1))
	}
	dropping.EndRequest("r1", Outcome{Latency: time.Millisecond})
	dropping.SetPipelineStats(mockTailStats(1000, 500), true)
	if !hasKey(dropping.Evaluate(), "pipeline-health:drops") {
		t.Errorf("dropped events mean the findings are computed from an incomplete record and that must be said out loud")
	}
	if dropping.Score().AnalysisHealthy {
		t.Errorf("a degraded pipeline must not report healthy analysis")
	}
	if dropping.Score().Posture != TierDegraded {
		t.Errorf("posture = %q; a blind analyzer is not a trusted one", dropping.Score().Posture)
	}
}

func TestDetectors_SilentPipelineDespiteTrafficIsReported(t *testing.T) {
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, PipelineHealth{})
	e.SetPipelineStats(mockTailStats(0, 0), true)
	e.BeginRequest("r1", "t", nil)
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{Latency: time.Millisecond})

	// Silence is only evidence of a broken pipeline once enough time has
	// passed for events to have arrived: gVisor writes its log
	// asynchronously, so a scan in the first moments of a session sees
	// nothing yet and that is normal.
	if hasKey(e.Evaluate(), "pipeline-health:silent") {
		t.Fatalf("silence within the grace period is events not having arrived yet, not a blind analyzer")
	}
	c.advance(30 * time.Second)
	if !hasKey(e.Evaluate(), "pipeline-health:silent") {
		t.Fatalf("requests served with zero observed syscalls means the analyzer is blind, not that the server is clean")
	}
}

func TestDetectors_ReliabilityNeverMovesTheSecurityTier(t *testing.T) {
	// §7.2: collapsing the two scores means a fast malicious server
	// outranks a slow safe one.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, ErrorRate{}, PipelineHealth{})
	e.SetPipelineStats(mockTailStats(100, 0), true)

	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("r%d", i)
		e.BeginRequest(id, "read_file", nil)
		c.advance(time.Millisecond)
		e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/x, O_RDONLY|0x0, 0o0`, 3))
		e.EndRequest(id, Outcome{Failed: i%2 == 0, Latency: time.Second, ToolName: "read_file"})
		c.advance(time.Millisecond)
	}

	sc := e.Score()
	if sc.Posture != TierTrusted {
		t.Fatalf("a 50%% error rate is an SLO problem, not a security one; posture = %q (%s)", sc.Posture, sc.PostureReason)
	}
	if sc.Reliability.ErrorRate < 0.4 {
		t.Fatalf("the reliability score must still show the failures: %v", sc.Reliability)
	}
	if !hasDetector(e.Evaluate(), "error-rate") {
		t.Fatalf("the failures must be reported, just not as a security finding")
	}
}

func TestScore_StatisticalCriticalCannotQuarantineOnItsOwn(t *testing.T) {
	// §1.1: a component fed attacker-influenceable input may narrow
	// trust, never widen it — and must not be able to take a server down
	// on its own either, or it becomes a denial-of-service surface.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, EgressVolume{}, PipelineHealth{})
	e.SetPipelineStats(mockTailStats(100, 0), true)

	e.BeginRequest("r1", "read_file", nil)
	c.advance(time.Millisecond)
	e.EndRequest("r1", Outcome{ResponseBytes: 10, Latency: time.Millisecond})
	c.advance(time.Second)
	e.Ingest(ev(c.now(), 1, "socket", `0x2, 0x1, 0x0`, 9))
	e.Ingest(ev(c.now(), 1, "write", `0x9, 0x1, 0x8000`, 32768))

	sc := e.Score()
	if sc.Posture != TierWatch {
		t.Fatalf("a statistical critical must cap at watch, got %q (%s)", sc.Posture, sc.PostureReason)
	}
	if sc.Critical == 0 {
		t.Fatalf("the finding must still be counted and visible")
	}
}

// helpers

func mockTailStats(ingested, dropped int64) observe.TailStats {
	return observe.TailStats{EventsParsed: ingested, LinesRead: ingested, Dropped: dropped}
}

func hasKey(fs []Finding, key string) bool {
	for _, f := range fs {
		if f.Key == key {
			return true
		}
	}
	return false
}

func severityOf(fs []Finding, key string) Severity {
	for _, f := range fs {
		if f.Key == key {
			return f.Severity
		}
	}
	return ""
}

func findByDetector(fs []Finding, name string) Finding {
	for _, f := range fs {
		if f.Detector == name {
			return f
		}
	}
	return Finding{}
}

func keys(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}

func TestDetectors_StartupHandshakeIsNotIdleActivity(t *testing.T) {
	// A Node runtime makes thousands of syscalls resolving modules before
	// it answers anything. If that landed in the idle window, every
	// healthy server would be reported as doing work nobody asked for —
	// and a detector that fires on every server is a detector that gets
	// turned off.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, IdleActivity{}, PathFanout{})

	e.BeginSynthetic("warmup:0", "mcp/handshake", []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize"}`))
	c.advance(time.Millisecond)
	for i := 0; i < 3000; i++ {
		e.Ingest(ev(c.now(), 1, "openat",
			fmt.Sprintf(`AT_FDCWD /, 0x1 /usr/lib/node_modules/p%d/index.js, O_RDONLY|0x0, 0o0`, i), 5))
	}
	c.advance(50 * time.Millisecond)
	e.EndRequest("warmup:0", Outcome{ResponseBytes: 300, Latency: 50 * time.Millisecond, Synthetic: true})

	runBenign(t, e, c, 40)

	fs := e.Evaluate()
	if hasDetector(fs, "idle-activity") {
		t.Errorf("startup must not be attributed to idle time: %v", keys(fs))
	}
	if hasDetector(fs, "path-fanout") {
		t.Errorf("startup fan-out must not be compared against per-request fan-out: %v", keys(fs))
	}
	snap := e.Snapshot()
	if snap.Requests != 40 {
		t.Errorf("request count = %d, want 40 — the handshake is not a client request", snap.Requests)
	}
	// But the behaviour itself is still on the record.
	if snap.Totals.Syscalls["openat"] < 3000 {
		t.Errorf("startup syscalls must still be counted in session totals, got %d", snap.Totals.Syscalls["openat"])
	}
}

func TestDetectors_SupplyChainDriftDuringStartupIsStillCaught(t *testing.T) {
	// The corollary: excluding startup from statistics must not exclude
	// it from analysis. Module loading is where a compromised dependency
	// actually shows up, and it happens at startup.
	b := BaselineFromProfile(benignProfile())
	e, c := newTestEngine(t, b, ModuleDrift{}, ReadThenEgress{})

	e.BeginSynthetic("warmup:0", "mcp/handshake", nil)
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /opt/rogue/node_modules/backdoor/index.js, O_RDONLY|0x0, 0o0`, 5))
	e.Ingest(ev(c.now(), 1, "read", `0x5, 0x1, 0x400`, 900))
	e.Ingest(ev(c.now(), 1, "openat", `AT_FDCWD /, 0x1 /srv/data/.aws/credentials, O_RDONLY|0x0, 0o0`, 6))
	e.Ingest(ev(c.now(), 1, "read", `0x6, 0x1, 0x400`, 200))
	c.advance(time.Millisecond)
	e.Ingest(ev(c.now(), 1, "socket", `0x2, 0x1, 0x0`, 9))
	e.Ingest(ev(c.now(), 1, "sendto", `0x9, 0x1, 0xc8, 0x0, 0x0, 0x0`, 200))
	c.advance(time.Millisecond)
	e.EndRequest("warmup:0", Outcome{ResponseBytes: 300, Latency: 3 * time.Millisecond, Synthetic: true})

	fs := e.Evaluate()
	if !hasDetector(fs, "module-drift") {
		t.Errorf("a dependency absent at approval must be caught even at startup: %v", keys(fs))
	}
	if !hasDetector(fs, "read-then-egress") {
		t.Errorf("credential exfiltration during the handshake is still exfiltration: %v", keys(fs))
	}
}
