// Package bridge wires the container pool's lifecycle events to the
// behavioural analyzer and the audit chain.
//
// It is its own package rather than a method on either side because it is
// the only component that legitimately knows about both: sandbox/analyze
// must not depend on how containers are pooled, and sandbox/pool must keep
// confining traffic whether or not anything is watching. Both the
// long-running daemon (cmd/warden-serve) and the interactive console
// (cmd/warden-console) need exactly this wiring, and a second copy of it
// would be a second place for the audit record to drift out of agreement
// with what the analyzer saw.
package bridge

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/audit"
	"mcp-warden/sandbox/pool"
	"mcp-warden/sandbox/registry"
	"mcp-warden/sandbox/runtime"
)

// Observer implements pool.Observer.
type Observer struct {
	mon   *analyze.Monitor
	log   *audit.Log
	runID atomic.Int64

	// Storage feeds the Exasol trust/reputation platform (see
	// sandbox/registry). Both fields are optional: a zero-value Observer
	// behaves exactly as it did before this existed. ServerID being empty
	// means "no server resolved for this session" and disables emission
	// without either field needing a nil check at every call site.
	mu      sync.Mutex
	openIDs map[string]string // containerID -> in-flight request id
	// pending tracks deferred event enrichment so teardown can wait for it.
	pending sync.WaitGroup

	Storage   *registry.Client
	ServerID  string
	SessionID string
	// Networks is the profile's declared network destinations, used only
	// to compute DESTINATION_DECLARED/MATCH — see emitRuntimeEvent.
	Networks []string
}

var _ pool.Observer = (*Observer)(nil)

// New creates an Observer feeding mon and, if non-nil, log.
func New(mon *analyze.Monitor, log *audit.Log) *Observer {
	return &Observer{mon: mon, log: log}
}

// OnFinding records a behavioural detection in the chain. Only new or
// escalated findings reach here, so the audit log grows with events worth
// reviewing rather than with traffic. Pass it as analyze.MonitorConfig's
// OnFinding.
func (o *Observer) OnFinding(containerID string, f analyze.Finding) {
	if o.Storage != nil && o.ServerID != "" {
		o.Storage.PostRuntimeFinding(o.ServerID, registry.RuntimeFinding{
			SessionID: o.SessionID,
			RequestID: f.RequestID,
			Detector:  f.Detector,
			Family:    string(f.Family),
			Severity:  string(f.Severity),
			// §7.2: a deterministic finding is a kernel-attested fact, a
			// statistical one is a judgement. The trust score weights them
			// differently, so the distinction has to survive the trip.
			Confidence:     string(f.Confidence),
			KernelAttested: f.Confidence == analyze.ConfidenceDeterministic,
			Title:          f.Title,
			Detail:         f.Detail,
			Evidence:       f.Evidence,
			Occurrences:    f.Count,
		})
	}
	if o.log == nil {
		return
	}
	o.log.Append(audit.Entry{
		Kind:      audit.KindFinding,
		RequestID: f.RequestID,
		Analysis: &audit.Analysis{
			Detector:   f.Detector,
			Family:     string(f.Family),
			Severity:   string(f.Severity),
			Confidence: string(f.Confidence),
			Title:      f.Title,
			Detail:     f.Detail,
			Evidence:   f.Evidence,
		},
		Lifecycle: &audit.Lifecycle{Event: "finding", ContainerID: containerID},
	})
}

func (o *Observer) ContainerStarted(id string) {
	o.mon.ContainerStarted(id)
	if o.log != nil {
		o.log.Append(audit.Entry{
			Kind:      audit.KindLifecycle,
			Lifecycle: &audit.Lifecycle{Event: "container_confined", ContainerID: id, State: "READY"},
		})
	}
}

func (o *Observer) ContainerStopped(id string) {
	if o.log != nil {
		o.log.Append(audit.Entry{
			Kind:      audit.KindLifecycle,
			Lifecycle: &audit.Lifecycle{Event: "container_destroyed", ContainerID: id, State: "DESTROYED"},
		})
	}
	o.mon.ContainerStopped(id)
}

func (o *Observer) RequestStarted(containerID string, req runtime.ExecRequest) {
	id := o.startRequestID(containerID, req)
	if req.ToolName == "mcp/handshake" {
		o.mon.RequestStartedSynthetic(containerID, id, req.ToolName, req.Payload)
		return
	}
	o.mon.RequestStarted(containerID, id, req.ToolName, req.Payload)
}

func (o *Observer) RequestFinished(containerID string, req runtime.ExecRequest, out pool.RequestOutcome) {
	id := o.finishRequestID(containerID, req)
	status := "SUCCESS"
	if out.Failed {
		status = "FAILED"
	}
	if out.Denial != "" {
		status = "DENIED"
	}

	o.mon.RequestFinished(containerID, id, analyze.Outcome{
		ResponseBytes: out.ResponseBytes,
		Unsolicited:   out.Unsolicited,
		Failed:        out.Failed,
		Denial:        out.Denial,
		Latency:       out.Latency,
		ToolName:      req.ToolName,
		Synthetic:     out.Synthetic,
	}, out.Response)

	// One §8.1 entry per call. The per-request behavioural counters come
	// from the container's own engine, so the entry records what the
	// kernel saw, not what the proxy assumed. Built whether or not an
	// audit log is attached, since the telemetry emission below reports
	// the same numbers.
	sb := &audit.Sandbox{
		Runtime:          "runsc",
		ContainerID:      containerID,
		NetworkConns:     0,
		AttributionExact: true,
	}
	var w *analyze.Window
	if win, ok := o.mon.LastWindow(containerID, id); ok {
		w = win
		sb.SyscallCount = w.SyscallCount()
		sb.DistinctPaths = w.DistinctPaths()
		sb.FileReadBytes = w.FileReadBytes
		sb.FileWriteBytes = w.FileWriteBytes
		sb.NetReadBytes = w.NetReadBytes
		sb.NetWriteBytes = w.NetWriteBytes
		sb.ProcessSpawns = w.Forks
		sb.UnsolicitedMsgs = w.Unsolicited
		sb.NetworkConns = len(w.Dials)
		sb.Anomalies = w.Denied
	}
	if out.Denial != "" {
		sb.SeccompDenials = 1
	}

	if o.log != nil {
		o.log.Append(audit.Entry{
			Kind:      audit.KindExecution,
			RequestID: id,
			Execution: &audit.Execution{
				ToolName:       req.ToolName,
				RPCPayloadHash: audit.HashPayload(req.Payload),
				Status:         status,
				LatencyMS:      out.Latency.Milliseconds(),
				RequestBytes:   len(req.Payload),
				ResponseBytes:  out.ResponseBytes,
			},
			Sandbox: sb,
		})
	}
	o.emitRuntimeEvent(id, req, out, w, sb, containerID)

	// gVisor writes its trace asynchronously, so the window above routinely
	// holds none of this call's syscalls yet: at this instant a tool that
	// just tried to read every credential store on the box is
	// indistinguishable from one that did nothing. Waiting before the first
	// emit would make the audit trail lag the traffic, so instead the row
	// goes out now and is corrected once the trace catches up. The event id
	// is stable and the write is an upsert, so this updates the same row
	// rather than adding a second one.
	o.scheduleEnrichment(id, req, out, containerID)
}

// enrichDelay is how long to wait for gVisor's trace before re-grading a
// call. Overridable because the lag scales with trace volume and host load.
func enrichDelay() time.Duration {
	if v := os.Getenv("WARDEN_EVENT_ENRICH_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 3 * time.Second
}

func (o *Observer) scheduleEnrichment(id string, req runtime.ExecRequest, out pool.RequestOutcome, containerID string) {
	if o.Storage == nil || o.ServerID == "" || req.ToolName == "mcp/handshake" {
		return
	}
	o.pending.Add(1)
	go func() {
		defer o.pending.Done()
		time.Sleep(enrichDelay())
		w, ok := o.mon.LastWindow(containerID, id)
		if !ok || w == nil {
			return
		}
		sb := &audit.Sandbox{
			Runtime: "runsc", ContainerID: containerID, AttributionExact: true,
			SyscallCount:    w.SyscallCount(),
			DistinctPaths:   w.DistinctPaths(),
			FileReadBytes:   w.FileReadBytes,
			FileWriteBytes:  w.FileWriteBytes,
			NetReadBytes:    w.NetReadBytes,
			NetWriteBytes:   w.NetWriteBytes,
			ProcessSpawns:   w.Forks,
			UnsolicitedMsgs: w.Unsolicited,
			NetworkConns:    len(w.Dials),
			Anomalies:       w.Denied,
		}
		if out.Denial != "" {
			sb.SeccompDenials = 1
		}
		o.emitRuntimeEvent(id, req, out, w, sb, containerID)
	}()
}

// Wait blocks until deferred event enrichment has finished. warden-serve
// calls it at teardown so a session's final rows reflect the whole trace
// rather than whatever had been parsed when the last call returned.
func (o *Observer) Wait() { o.pending.Wait() }

// emitRuntimeEvent sends one FACT_RUNTIME_EVENTS row for this call. It
// reuses exactly the window data already fetched above rather than
// re-deriving anything from the analyzer, so this can never disagree with
// what the audit entry just recorded. Best-effort and fire-and-forget: see
// sandbox/registry's own doc comment for why.
func (o *Observer) emitRuntimeEvent(id string, req runtime.ExecRequest, out pool.RequestOutcome, w *analyze.Window, sb *audit.Sandbox, containerID string) {
	if o.Storage == nil || o.ServerID == "" || req.ToolName == "mcp/handshake" {
		return
	}
	ev := o.assessCall(req, out, w)
	decision, reason, statusCode := ev.decision, ev.reason, ev.statusCode
	sensitive, categories := ev.sensitive, ev.categories
	actualDest, match := ev.actualDest, ev.destinationMatch
	declared := strings.Join(o.Networks, ",")
	// This is a coarse, dashboard-facing signal, not a security decision —
	// sandbox/analyze's NetworkDrift detector is the authoritative,
	// deterministic source for confinement gaps; this column just mirrors
	// its verdict for the audit trail.

	o.Storage.PostRuntimeEvent(o.ServerID, registry.RuntimeEvent{
		// Request ids restart at req_000001 in every session, so the
		// session id has to be part of the event's primary key: without
		// it, a second session's calls collide with the first's and the
		// upsert silently keeps the older row, losing the newer call
		// entirely. An audit trail that drops records without erroring is
		// worse than one that isn't there.
		EventID:                 o.SessionID + ":" + id,
		ToolName:                req.ToolName,
		SessionID:               o.SessionID,
		RequestID:               id,
		ContainerID:             containerID,
		RPCPayloadHash:          audit.HashPayload(req.Payload),
		LearningMode:            false, // this path only ever runs confined
		Posture:                 string(o.mon.Score().Posture),
		DestinationDeclared:     declared,
		DestinationActual:       actualDest,
		DestinationMatch:        &match,
		SensitiveDataFlag:       sensitive,
		SensitiveDataCategories: categories,
		Decision:                decision,
		DecisionReason:          reason,
		LatencyMS:               out.Latency.Milliseconds(),
		StatusCode:              statusCode,
		BytesSent:               len(req.Payload),
		BytesReceived:           out.ResponseBytes,
		SyscallCount:            sb.SyscallCount,
		DistinctPaths:           sb.DistinctPaths,
		FileReadBytes:           sb.FileReadBytes,
		FileWriteBytes:          sb.FileWriteBytes,
		NetReadBytes:            sb.NetReadBytes,
		NetWriteBytes:           sb.NetWriteBytes,
		ProcessSpawns:           sb.ProcessSpawns,
		SeccompDenials:          sb.SeccompDenials,
		UnsolicitedMsg:          sb.UnsolicitedMsgs,
		Severity:                ev.severity,
		Evidence:                ev.evidence,
	})
}

// callAssessment is the per-call security verdict: what this one request
// did, graded on its own evidence.
type callAssessment struct {
	decision         string
	reason           string
	severity         string
	statusCode       int
	sensitive        bool
	categories       []string
	evidence         []string
	actualDest       string
	destinationMatch bool
}

var severityRank = map[string]int{"": 0, "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func (a *callAssessment) note(severity, reason, evidence string) {
	a.evidence = append(a.evidence, evidence)
	if severityRank[severity] > severityRank[a.severity] {
		a.severity = severity
		// The reason column reports the most serious thing observed;
		// everything else stays in evidence rather than being lost.
		a.reason = reason
	}
	if a.decision == "ALLOWED" && severityRank[severity] >= severityRank["low"] {
		a.decision = "FLAGGED"
	}
}

// assessCall grades a single request from the window the kernel produced
// for it.
//
// It deliberately does not consult the session's detector findings. Those
// are session-scoped and deduplicated by design - a detector reports a
// behaviour the first time it appears and stays quiet afterwards - so
// colouring individual calls from them marks the first offending call and
// reports every later identical one as clean. The same tool exfiltrating
// credentials on ten consecutive calls would show one flagged row and nine
// that read as ordinary traffic, which is worse than no signal at all,
// because it invites the reader to conclude the behaviour stopped.
//
// The window is per-request and carries the raw observations, so grading
// from it gives every call an independently correct verdict.
func (o *Observer) assessCall(req runtime.ExecRequest, out pool.RequestOutcome, w *analyze.Window) callAssessment {
	a := callAssessment{decision: "ALLOWED", destinationMatch: true}
	switch {
	case out.Denial != "":
		a.decision, a.reason, a.statusCode, a.severity = "BLOCKED", out.Denial, 2, "critical"
		a.evidence = append(a.evidence, "supervisor denial: "+out.Denial)
	case out.Failed:
		a.decision, a.reason, a.statusCode, a.severity = "FLAGGED", "request failed", 1, "low"
	}
	if w == nil {
		return a
	}

	// Operations the kernel refused during this call. out.Denial is the
	// pool's own signal and only fires when the supervisor quarantines the
	// container; a call that merely had several syscalls refused completes
	// normally and would otherwise read as ALLOWED, which is true of the
	// call and misleading about what it tried to do.
	if len(w.Denied) > 0 {
		a.note("high",
			fmt.Sprintf("%d operation(s) refused by the kernel during this call", len(w.Denied)),
			"kernel refused: "+strings.Join(w.Denied, ", "))
	}

	// Credential-shaped paths touched during this call. A refused attempt
	// matters as much as a successful read - arguably more, since it shows
	// intent that confinement happened to stop - so both are reported, and
	// the distinction is kept in the evidence rather than collapsed.
	var readCreds, refusedCreds []string
	for p, acc := range w.Paths {
		if !analyze.IsSensitivePath(p) || acc.Kind == analyze.AccessStat {
			continue
		}
		if acc.ReadBytes > 0 || acc.WriteBytes > 0 {
			readCreds = append(readCreds, fmt.Sprintf("%s (%d bytes)", p, acc.ReadBytes+acc.WriteBytes))
		} else {
			refusedCreds = append(refusedCreds, fmt.Sprintf("%s (%d failed open(s))", p, acc.Errors))
		}
	}
	sort.Strings(readCreds)
	sort.Strings(refusedCreds)
	if len(readCreds) > 0 {
		a.sensitive = true
		a.categories = append(a.categories, "credential_file_read")
		a.note("critical",
			fmt.Sprintf("read %d credential-shaped file(s) during this call", len(readCreds)),
			"credential read: "+strings.Join(readCreds, ", "))
	}
	if len(refusedCreds) > 0 {
		a.sensitive = true
		a.categories = append(a.categories, "credential_file_access_attempt")
		a.note("high",
			fmt.Sprintf("attempted %d credential-shaped path(s); confinement refused them", len(refusedCreds)),
			"credential access refused: "+strings.Join(refusedCreds, ", "))
	}

	// Reading another process's environment block is credential harvesting:
	// tokens and keys are passed to processes as environment variables far
	// more often than they are written to a file. analyze's sensitive-path
	// list deliberately stays narrow (an earlier broad version produced 543
	// meaningless findings on one run), so this is called out here as its
	// own signal rather than by widening that list.
	var environReads []string
	for p, acc := range w.Paths {
		if acc.Kind == analyze.AccessStat {
			continue
		}
		if strings.HasPrefix(p, "/proc/") && strings.HasSuffix(p, "/environ") {
			environReads = append(environReads, p)
		}
	}
	sort.Strings(environReads)
	if len(environReads) > 0 {
		a.sensitive = true
		a.categories = append(a.categories, "process_environment_read")
		a.note("high",
			fmt.Sprintf("read %d process environment block(s)", len(environReads)),
			"process environment read: "+strings.Join(environReads, ", "))
	}

	// Anything executed beyond the declared entrypoint.
	if len(w.Execs) > 0 {
		a.note("high",
			fmt.Sprintf("%d process(es) executed beyond the entrypoint", len(w.Execs)),
			"exec: "+strings.Join(w.Execs, ", "))
	} else if w.Forks > 0 {
		a.note("low",
			fmt.Sprintf("%d process/thread creation(s) while serving this call", w.Forks),
			fmt.Sprintf("forks: %d", w.Forks))
	}

	if len(w.SecretHits) > 0 {
		a.sensitive = true
		a.categories = append(a.categories, w.SecretHits...)
		a.note("high", "response carried credential-shaped content",
			"secret patterns in response: "+strings.Join(w.SecretHits, ", "))
	}
	if len(w.InjectionHits) > 0 {
		a.sensitive = true
		a.categories = append(a.categories, w.InjectionHits...)
		a.note("medium", "response carried instruction-shaped content (prompt injection)",
			"injection patterns in response: "+strings.Join(w.InjectionHits, ", "))
	}

	if len(w.Dials) > 0 {
		declaredSet := make(map[string]bool, len(o.Networks))
		for _, n := range o.Networks {
			declaredSet[n] = true
		}
		dests := make([]string, 0, len(w.Dials))
		var undeclared []string
		for d := range w.Dials {
			dests = append(dests, d)
			if !declaredSet[d] {
				a.destinationMatch = false
				undeclared = append(undeclared, d)
			}
		}
		sort.Strings(dests)
		sort.Strings(undeclared)
		a.actualDest = strings.Join(dests, ",")
		if len(undeclared) > 0 {
			a.note("critical", "connected to a destination outside the declared profile",
				"undeclared destination: "+strings.Join(undeclared, ", "))
		}
	}

	// Reading credentials and then writing to the network within one call
	// is the exfiltration shape per-call authorization structurally cannot
	// see, so it is graded above either half on its own.
	if len(readCreds) > 0 && w.NetWriteBytes > 0 {
		a.note("critical", "credential read followed by network egress in the same call",
			fmt.Sprintf("read-then-egress: %d credential file(s), %d bytes written to network",
				len(readCreds), w.NetWriteBytes))
	}

	if a.severity == "" {
		a.severity = "none"
	}
	return a
}

// startRequestID returns the caller's request id, or mints one and
// remembers it for the matching RequestFinished. Every entry in the chain
// needs an identifier even when the client did not supply one, or
// violations cannot be attributed after the fact.
//
// Minting one independently at each end does not work, and failing quietly
// is what makes it worth a comment: start and finish would get different
// ids, every LastWindow lookup would miss, and the audit entry's whole
// sandbox block — syscall counts, bytes, denials — would record zeros for
// a call that did plenty. §6.3 serialises requests within a container, so
// one in-flight id per container is exactly the right amount of state.
func (o *Observer) startRequestID(containerID string, req runtime.ExecRequest) string {
	if req.RequestID != "" {
		return req.RequestID
	}
	id := fmt.Sprintf("req_%06d", o.runID.Add(1))
	o.mu.Lock()
	if o.openIDs == nil {
		o.openIDs = map[string]string{}
	}
	o.openIDs[containerID] = id
	o.mu.Unlock()
	return id
}

// finishRequestID returns the id RequestStarted used for this container's
// in-flight call.
func (o *Observer) finishRequestID(containerID string, req runtime.ExecRequest) string {
	if req.RequestID != "" {
		return req.RequestID
	}
	o.mu.Lock()
	id, ok := o.openIDs[containerID]
	delete(o.openIDs, containerID)
	o.mu.Unlock()
	if ok {
		return id
	}
	return fmt.Sprintf("req_%06d", o.runID.Add(1))
}

// PostSession records the closing summary for this session — posture,
// finding counts, traffic, and the sandbox totals — as one FACT_SESSION
// row. Called once, as the console tears the session down, and
// synchronously: there is no later opportunity to send it.
//
// confinement distinguishes the full §6.1 stack from the unprivileged
// subset (seccomp and mounts, no cgroup limits), because "clean session"
// means something different under each and a reader cannot tell them apart
// from the findings alone.
func (o *Observer) PostSession(ctx context.Context, startedAt time.Time, confinement string, auditEntries int64) error {
	if o.Storage == nil || o.ServerID == "" {
		return nil
	}
	sc := o.mon.Score()
	snap := o.mon.Aggregate()

	s := registry.SessionSummary{
		SessionID:       o.SessionID,
		StartedAt:       startedAt.UTC().Format(time.RFC3339Nano),
		EndedAt:         time.Now().UTC().Format(time.RFC3339Nano),
		DurationSeconds: time.Since(startedAt).Seconds(),
		Posture:         string(sc.Posture),
		PostureReason:   sc.PostureReason,
		Critical:        sc.Critical,
		High:            sc.High,
		Medium:          sc.Medium,
		Low:             sc.Low,
		KernelAttested:  sc.Deterministic,
		Requests:        sc.Reliability.Requests,
		Failures:        sc.Reliability.Failures,
		P50LatencyMS:    sc.Reliability.P50.Milliseconds(),
		P99LatencyMS:    sc.Reliability.P99.Milliseconds(),
		AnalysisHealthy: sc.AnalysisHealthy,
		LearningMode:    false,
		Confinement:     confinement,
		Runtime:         "runsc",
		AuditEntries:    auditEntries,
		// The chain is verified by warden-audit -verify, not here: this
		// records that a chain exists and how long it is, and a reader who
		// needs the proof runs the verifier against the file itself.
		AuditChainVerified: false,
	}
	if snap != nil {
		s.Denials = snap.Denials
		s.P95LatencyMS = snap.Latency.P95.Milliseconds()
		if t := snap.Totals; t != nil {
			s.SyscallCount = t.SyscallCount()
			s.DistinctPaths = t.DistinctPaths()
			s.FileReadBytes = t.FileReadBytes
			s.FileWriteBytes = t.FileWriteBytes
			s.NetWriteBytes = t.NetWriteBytes
			s.ProcessSpawns = t.Forks
		}
	}
	return o.Storage.PostSession(ctx, o.ServerID, s)
}

// Handshake is the exchange every MCP stdio server expects before it will
// serve a tool call: initialize, the initialized notification, then
// tools/list. Running it per container is what makes a pool of
// independent server processes usable behind one endpoint.
func Handshake(timeout time.Duration) []runtime.ExecRequest {
	return []runtime.ExecRequest{
		{
			RequestID: "warmup:initialize", ToolName: "mcp/handshake", Timeout: timeout,
			Payload: []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-warden","version":"0.1"}}}`),
		},
		{
			RequestID: "warmup:initialized", ToolName: "mcp/handshake", Timeout: timeout, Notify: true,
			Payload: []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
		},
		{
			RequestID: "warmup:tools-list", ToolName: "mcp/handshake", Timeout: timeout,
			Payload: []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`),
		},
	}
}
