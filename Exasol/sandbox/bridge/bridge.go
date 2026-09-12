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
}

// emitRuntimeEvent sends one FACT_RUNTIME_EVENTS row for this call. It
// reuses exactly the window data already fetched above rather than
// re-deriving anything from the analyzer, so this can never disagree with
// what the audit entry just recorded. Best-effort and fire-and-forget: see
// sandbox/registry's own doc comment for why.
func (o *Observer) emitRuntimeEvent(id string, req runtime.ExecRequest, out pool.RequestOutcome, w *analyze.Window, sb *audit.Sandbox, containerID string) {
	if o.Storage == nil || o.ServerID == "" || req.ToolName == "mcp/handshake" {
		return
	}
	decision, reason := "ALLOWED", ""
	statusCode := 0
	switch {
	case out.Denial != "":
		decision, reason, statusCode = "BLOCKED", out.Denial, 2
	case out.Failed:
		decision, reason, statusCode = "FLAGGED", "request failed", 1
	}
	var sensitive bool
	var categories []string
	var actualDest string
	match := true // vacuously true when nothing was dialed
	if w != nil {
		// Operations the kernel refused during this call. out.Denial is the
		// pool's own signal and only fires when the supervisor quarantines
		// the container; a call that merely had several syscalls refused
		// completes normally and would otherwise read as ALLOWED, which is
		// true of the call and misleading about what it tried to do.
		if len(w.Denied) > 0 && decision == "ALLOWED" {
			decision = "FLAGGED"
			reason = fmt.Sprintf("%d operation(s) refused by the kernel during this call", len(w.Denied))
		}
		if len(w.SecretHits) > 0 || len(w.InjectionHits) > 0 {
			sensitive = true
			categories = append(append([]string{}, w.SecretHits...), w.InjectionHits...)
			if decision == "ALLOWED" {
				decision, reason = "FLAGGED", "response content matched a secret or injection pattern"
			}
		}
		if len(w.Dials) > 0 {
			declaredSet := make(map[string]bool, len(o.Networks))
			for _, n := range o.Networks {
				declaredSet[n] = true
			}
			dests := make([]string, 0, len(w.Dials))
			for d := range w.Dials {
				dests = append(dests, d)
				if !declaredSet[d] {
					match = false
				}
			}
			actualDest = strings.Join(dests, ",")
			if !match && decision == "ALLOWED" {
				decision, reason = "FLAGGED", "connection to a destination outside the declared profile"
			}
		}
	}
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
		ProcessSpawns:           sb.ProcessSpawns,
		SeccompDenials:          sb.SeccompDenials,
		UnsolicitedMsg:          sb.UnsolicitedMsgs,
	})
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
