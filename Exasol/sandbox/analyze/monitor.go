package analyze

import (
	"context"
	"sort"
	"sync"
	"time"

	"mcp-warden/sandbox/observe"
)

// TraceLocator reports where a container's trace log is written, and
// whether tracing is on for it at all.
type TraceLocator func(containerID string) (dir string, ok bool)

// MonitorConfig configures a Monitor.
type MonitorConfig struct {
	Baseline  *Baseline
	Detectors []Detector
	// Locate finds a container's trace directory. Required for analysis
	// to do anything; a Monitor with no locator still tracks requests and
	// outcomes, which keeps the reliability half working when tracing is
	// off.
	Locate TraceLocator
	// EvaluateEvery is how often detectors run. Defaults to 2s.
	//
	// Evaluation is periodic rather than per-request because events
	// arrive after the request that produced them has already returned:
	// the sentry writes its log asynchronously. Scoring at response time
	// would systematically miss whatever a server did at the end of a
	// call.
	EvaluateEvery time.Duration
	// MaxTraceBytesPerContainer bounds on-disk trace growth. Defaults to
	// 512MB.
	MaxTraceBytesPerContainer int64
	// OnFinding is called once per newly-raised or newly-escalated
	// finding, with the container it came from.
	OnFinding func(containerID string, f Finding)
	// RetainContainers bounds how many finished containers' snapshots are
	// kept for per-container drill-down. Findings survive regardless;
	// this only bounds the detailed view.
	RetainContainers int
}

// Monitor runs one Engine per container and merges their results into a
// single session view.
//
// One engine per container, rather than one per Monitor, is forced by
// attribution: §6.3's serialization guarantee holds *within* a container,
// so a request's syscalls are only unambiguously identifiable if each
// container's stream is analysed separately. Merging happens afterwards,
// on findings — which are already deduplicated by key — rather than on
// raw events, where it would destroy the very attribution the design
// exists to provide.
type Monitor struct {
	cfg MonitorConfig

	mu        sync.Mutex
	engines   map[string]*containerState
	retired   []*retiredContainer
	findings  map[string]*Finding
	closed    bool
	lastEval  time.Time
	requests  int
	tracingOn bool
}

type containerState struct {
	id     string
	engine *Engine
	tailer *observe.Tailer
	cancel context.CancelFunc
	done   chan struct{}
	// openReq is the request currently attributed to this container,
	// retained so a finished request can be matched to its start even if
	// the caller passes a different ExecRequest value.
	openReq string
	started time.Time
}

type retiredContainer struct {
	ID       string    `json:"container_id"`
	Started  time.Time `json:"started"`
	Stopped  time.Time `json:"stopped"`
	Requests int       `json:"requests"`
	Snapshot *Snapshot `json:"snapshot"`
}

// NewMonitor creates a monitor. It starts no goroutines until a container
// is registered.
func NewMonitor(cfg MonitorConfig) *Monitor {
	if cfg.EvaluateEvery <= 0 {
		cfg.EvaluateEvery = 2 * time.Second
	}
	if cfg.MaxTraceBytesPerContainer <= 0 {
		cfg.MaxTraceBytesPerContainer = 512 << 20
	}
	if cfg.RetainContainers <= 0 {
		cfg.RetainContainers = 8
	}
	if cfg.Baseline == nil {
		cfg.Baseline = &Baseline{}
	}
	if len(cfg.Detectors) == 0 {
		cfg.Detectors = DefaultDetectors()
	}
	return &Monitor{
		cfg:      cfg,
		engines:  map[string]*containerState{},
		findings: map[string]*Finding{},
	}
}

// ContainerStarted registers a container and begins tailing its trace.
func (m *Monitor) ContainerStarted(containerID string) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if _, exists := m.engines[containerID]; exists {
		m.mu.Unlock()
		return
	}

	eng := NewEngine(m.cfg.Baseline, m.cfg.Detectors, Options{
		OnFinding: func(f Finding) {
			if m.cfg.OnFinding != nil {
				m.cfg.OnFinding(containerID, f)
			}
		},
	})
	cs := &containerState{id: containerID, engine: eng, started: time.Now()}
	m.engines[containerID] = cs

	var dir string
	var tracing bool
	if m.cfg.Locate != nil {
		dir, tracing = m.cfg.Locate(containerID)
	}
	if tracing {
		m.tracingOn = true
	}
	m.mu.Unlock()

	if measured, ok := m.cfg.Baseline.Measured(); ok {
		eng.SetEntrypoint(measured)
	}
	eng.SetPipelineStats(observe.TailStats{}, tracing)
	if !tracing {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	tailer := &observe.Tailer{Dir: dir, MaxBytesPerFile: m.cfg.MaxTraceBytesPerContainer}
	cs.tailer = tailer
	cs.cancel = cancel
	cs.done = make(chan struct{})

	events := tailer.Follow(ctx)
	go func() {
		defer close(cs.done)
		eng.Consume(events)
	}()
	// Keep the engine's view of pipeline health current, so "no findings"
	// can be distinguished from "no visibility".
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				eng.SetPipelineStats(tailer.Stats(), true)
				return
			case <-t.C:
				eng.SetPipelineStats(tailer.Stats(), true)
			}
		}
	}()
}

// ContainerStopped stops tailing and folds the container's final state
// into the retired set.
func (m *Monitor) ContainerStopped(containerID string) {
	m.mu.Lock()
	cs, ok := m.engines[containerID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.engines, containerID)
	m.mu.Unlock()

	// A final evaluation before teardown: the last thing a container does
	// before being destroyed — especially a quarantined one — is often
	// the most interesting thing it does.
	m.mergeFindings(containerID, cs.engine.Evaluate())
	snap := cs.engine.Snapshot()

	if cs.cancel != nil {
		cs.cancel()
		select {
		case <-cs.done:
		case <-time.After(2 * time.Second):
			// The tailer is stuck; the engine's state is still valid, so
			// take it and move on rather than blocking teardown.
		}
	}

	m.mu.Lock()
	m.retired = append(m.retired, &retiredContainer{
		ID: containerID, Started: cs.started, Stopped: time.Now(),
		Requests: snap.Requests, Snapshot: snap,
	})
	if len(m.retired) > m.cfg.RetainContainers {
		m.retired = m.retired[len(m.retired)-m.cfg.RetainContainers:]
	}
	m.mu.Unlock()
}

// RequestStarted opens an attribution window on the container's engine.
func (m *Monitor) RequestStarted(containerID, requestID, toolName string, payload []byte) {
	if cs, ok := m.openWindow(containerID, requestID); ok {
		cs.engine.BeginRequest(requestID, toolName, payload)
	}
}

// RequestStartedSynthetic opens a window for a proxy-initiated exchange,
// such as the MCP handshake run against every new container.
func (m *Monitor) RequestStartedSynthetic(containerID, requestID, label string, payload []byte) {
	if cs, ok := m.openWindow(containerID, requestID); ok {
		cs.engine.BeginSynthetic(requestID, label, payload)
	}
}

func (m *Monitor) openWindow(containerID, requestID string) (*containerState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs, ok := m.engines[containerID]
	if !ok {
		return nil, false
	}
	cs.openReq = requestID
	m.requests++
	return cs, true
}

// LastWindow returns the completed window for one request, for callers
// that need the kernel-observed counters at the moment a call finished —
// chiefly the audit log's §8.1 sandbox block.
func (m *Monitor) LastWindow(containerID, requestID string) (*Window, bool) {
	m.mu.Lock()
	cs, ok := m.engines[containerID]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	snap := cs.engine.Snapshot()
	for i := len(snap.Recent) - 1; i >= 0; i-- {
		if snap.Recent[i].RequestID == requestID {
			return snap.Recent[i], true
		}
	}
	return nil, false
}

// RequestFinished closes the window and records the outcome.
func (m *Monitor) RequestFinished(containerID, requestID string, out Outcome, response []byte) {
	m.mu.Lock()
	cs, ok := m.engines[containerID]
	if ok && requestID == "" {
		requestID = cs.openReq
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	if len(response) > 0 {
		cs.engine.ObserveResponse(response)
	}
	cs.engine.EndRequest(requestID, out)
}

// ObserveResponse feeds a response payload to one container's engine for
// protocol-layer inspection — chiefly manifest pinning, which can only
// happen at the moment the manifest passes through.
func (m *Monitor) ObserveResponse(containerID string, payload []byte) {
	m.mu.Lock()
	cs, ok := m.engines[containerID]
	m.mu.Unlock()
	if ok && len(payload) > 0 {
		cs.engine.ObserveResponse(payload)
	}
}

// Evaluate runs detectors across every live container and returns the
// merged session finding set.
func (m *Monitor) Evaluate() []Finding {
	m.mu.Lock()
	live := make([]*containerState, 0, len(m.engines))
	for _, cs := range m.engines {
		live = append(live, cs)
	}
	m.lastEval = time.Now()
	m.mu.Unlock()

	for _, cs := range live {
		m.mergeFindings(cs.id, cs.engine.Evaluate())
	}
	return m.Findings()
}

// Run evaluates on a ticker until ctx is cancelled. This is the normal
// way to drive a Monitor in a long-running daemon.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.EvaluateEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Evaluate()
		}
	}
}

// mergeFindings folds one container's findings into the session set.
// Severity takes the maximum and counts sum: a condition seen on two
// containers is more established, not less, and the worst observation is
// the one that should drive the tier.
func (m *Monitor) mergeFindings(containerID string, fs []Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range fs {
		existing, ok := m.findings[f.Key]
		if !ok {
			cp := f
			m.findings[f.Key] = &cp
			continue
		}
		if f.Severity.Rank() > existing.Severity.Rank() {
			existing.Severity = f.Severity
			existing.Confidence = f.Confidence
			existing.Title = f.Title
		}
		existing.Detail = f.Detail
		existing.addEvidence(f.Evidence...)
		if f.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = f.LastSeen
		}
		if f.Count > existing.Count {
			existing.Count = f.Count
		}
	}
}

// Findings returns the merged session finding set.
func (m *Monitor) Findings() []Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Finding, 0, len(m.findings))
	for _, f := range m.findings {
		out = append(out, *f)
	}
	SortFindings(out)
	return out
}

// Score computes the session posture and reliability from the merged
// findings, applying the identical tier rules a single Engine uses.
func (m *Monitor) Score() Score {
	// See Engine.Score: a stale score is a dangerous score.
	findings := m.Evaluate()
	agg := m.Aggregate()

	sc := Score{Posture: TierTrusted, PostureReason: "no deviation observed", AnalysisHealthy: true}
	var detCritical, detHigh, statCritical, anyMedium bool
	for _, f := range findings {
		if f.Family == FamilyReliability {
			if f.Detector == (PipelineHealth{}).Name() && f.Severity.Rank() >= SeverityMedium.Rank() {
				sc.AnalysisHealthy = false
			}
			continue
		}
		if !securityFamilies[f.Family] {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			sc.Critical++
		case SeverityHigh:
			sc.High++
		case SeverityMedium:
			sc.Medium++
		case SeverityLow:
			sc.Low++
		default:
			sc.Info++
		}
		if f.Confidence == ConfidenceDeterministic {
			sc.Deterministic++
		}
		switch {
		case f.Severity == SeverityCritical && f.Confidence == ConfidenceDeterministic:
			detCritical = true
		case f.Severity == SeverityCritical:
			statCritical = true
		case f.Severity == SeverityHigh && f.Confidence == ConfidenceDeterministic:
			detHigh = true
		case f.Severity == SeverityMedium:
			anyMedium = true
		}
	}

	switch {
	case detCritical:
		sc.Posture = TierQuarantine
		sc.PostureReason = "confirmed confinement gap or exfiltration-shaped sequence"
	case detHigh:
		sc.Posture = TierDegraded
		sc.PostureReason = "confirmed deviation from the approved capability profile"
	case !sc.AnalysisHealthy:
		sc.Posture = TierDegraded
		sc.PostureReason = "behavioural analysis is degraded; absence of findings is not evidence of safety"
	case statCritical:
		sc.Posture = TierWatch
		sc.PostureReason = "advisory detector raised a critical signal; not kernel-attested"
	case sc.High > 0 || anyMedium:
		sc.Posture = TierWatch
		sc.PostureReason = "advisory signals outside the deterministic set"
	}

	sc.Reliability = Reliability{
		Requests:     agg.Requests,
		Failures:     agg.Failures,
		P50:          agg.Latency.P50,
		P99:          agg.Latency.P99,
		UptimeSecond: agg.Uptime,
	}
	if agg.Requests > 0 {
		sc.Reliability.ErrorRate = float64(agg.Failures) / float64(agg.Requests)
	}
	return sc
}

// Narrative builds a correlated, human-readable summary of the current
// session findings. See BuildNarrative for what "correlated" means here.
func (m *Monitor) Narrative() Narrative {
	return BuildNarrative(m.Score(), m.Findings())
}

// Aggregate returns a merged snapshot across live containers, for the
// dashboard's session-level view.
func (m *Monitor) Aggregate() *Snapshot {
	m.mu.Lock()
	live := make([]*containerState, 0, len(m.engines))
	for _, cs := range m.engines {
		live = append(live, cs)
	}
	retired := append([]*retiredContainer(nil), m.retired...)
	tracing := m.tracingOn
	m.mu.Unlock()

	sort.Slice(live, func(i, j int) bool { return live[i].id < live[j].id })

	out := &Snapshot{
		TakenAt:     time.Now(),
		Baseline:    m.cfg.Baseline,
		Totals:      newWindow("", time.Now()),
		Idle:        newWindow("", time.Now()),
		ToolLatency: map[string]Percentiles{},
	}
	out.Idle.Idle = true
	out.Stats.TracingEnabled = tracing

	var latencies []time.Duration
	earliest := time.Time{}
	snaps := make([]*Snapshot, 0, len(live)+len(retired))
	for _, cs := range live {
		snaps = append(snaps, cs.engine.Snapshot())
	}
	for _, r := range retired {
		snaps = append(snaps, r.Snapshot)
	}

	for _, s := range snaps {
		if s == nil {
			continue
		}
		out.Totals.merge(s.Totals)
		out.Idle.merge(s.Idle)
		out.Requests += s.Requests
		out.Failures += s.Failures
		out.Denials += s.Denials
		out.Unattributed += s.Unattributed
		out.Stats.EventsIngested += s.Stats.EventsIngested
		out.Stats.EventsDropped += s.Stats.EventsDropped
		out.Stats.LinesRead += s.Stats.LinesRead
		out.Stats.BytesRead += s.Stats.BytesRead
		out.Stats.LogTruncations += s.Stats.LogTruncations
		if s.Stats.LastEventAt.After(out.Stats.LastEventAt) {
			out.Stats.LastEventAt = s.Stats.LastEventAt
		}
		if out.Entrypoint.SHA256 == "" && s.Entrypoint.SHA256 != "" {
			out.Entrypoint = s.Entrypoint
		}
		if out.ManifestHash == "" {
			out.ManifestHash = s.ManifestHash
		}
		out.Recent = append(out.Recent, s.Recent...)
		out.IdleBursts = append(out.IdleBursts, s.IdleBursts...)
		if earliest.IsZero() || (!s.StartedAt.IsZero() && s.StartedAt.Before(earliest)) {
			earliest = s.StartedAt
		}
		// Percentiles cannot be merged exactly without the underlying
		// samples, and keeping every container's samples for the life of
		// the daemon is not worth exact session-level quantiles. The
		// session view therefore summarises from each container's own
		// summary and says so; exact percentiles remain available
		// per-container and in the Prometheus histogram.
		if s.Latency.Count > 0 {
			latencies = append(latencies, s.Latency.P50, s.Latency.P99, s.Latency.Max)
		}
		for tool, p := range s.ToolLatency {
			if have, ok := out.ToolLatency[tool]; !ok || p.P99 > have.P99 {
				out.ToolLatency[tool] = p
			}
		}
	}

	sort.Slice(out.Recent, func(i, j int) bool { return out.Recent[i].Start.Before(out.Recent[j].Start) })
	sort.Slice(out.IdleBursts, func(i, j int) bool { return out.IdleBursts[i].Before(out.IdleBursts[j]) })
	out.Latency = percentiles(latencies)
	if earliest.IsZero() {
		earliest = out.TakenAt
	}
	out.StartedAt = earliest
	out.Uptime = out.TakenAt.Sub(earliest).Seconds()
	return out
}

// Containers returns a per-container view for drill-down.
func (m *Monitor) Containers() []ContainerView {
	m.mu.Lock()
	live := make([]*containerState, 0, len(m.engines))
	for _, cs := range m.engines {
		live = append(live, cs)
	}
	retired := append([]*retiredContainer(nil), m.retired...)
	m.mu.Unlock()

	out := make([]ContainerView, 0, len(live)+len(retired))
	for _, cs := range live {
		s := cs.engine.Snapshot()
		out = append(out, ContainerView{
			ID: cs.id, Live: true, Started: cs.started,
			Requests: s.Requests, Failures: s.Failures, Denials: s.Denials,
			Events: s.Stats.EventsIngested, Dropped: s.Stats.EventsDropped,
			DistinctPaths: s.Totals.DistinctPaths(),
			FileReadBytes: s.Totals.FileReadBytes, NetWriteBytes: s.Totals.NetWriteBytes,
			Score: cs.engine.Score(),
		})
	}
	for _, r := range retired {
		out = append(out, ContainerView{
			ID: r.ID, Live: false, Started: r.Started, Stopped: r.Stopped,
			Requests: r.Requests,
			Failures: r.Snapshot.Failures, Denials: r.Snapshot.Denials,
			Events: r.Snapshot.Stats.EventsIngested, Dropped: r.Snapshot.Stats.EventsDropped,
			DistinctPaths: r.Snapshot.Totals.DistinctPaths(),
			FileReadBytes: r.Snapshot.Totals.FileReadBytes, NetWriteBytes: r.Snapshot.Totals.NetWriteBytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// ContainerView is one container's summary for the dashboard.
type ContainerView struct {
	ID            string    `json:"container_id"`
	Live          bool      `json:"live"`
	Started       time.Time `json:"started"`
	Stopped       time.Time `json:"stopped,omitempty"`
	Requests      int       `json:"requests"`
	Failures      int       `json:"failures"`
	Denials       int       `json:"denials"`
	Events        int64     `json:"events"`
	Dropped       int64     `json:"dropped"`
	DistinctPaths int       `json:"distinct_paths"`
	FileReadBytes int64     `json:"file_read_bytes"`
	NetWriteBytes int64     `json:"net_write_bytes"`
	Score         Score     `json:"score,omitempty"`
}

// SetEntrypoint records the measured entrypoint on every engine, present
// and future.
func (m *Monitor) SetEntrypoint(id EntrypointIdentity) {
	m.mu.Lock()
	m.cfg.Baseline.measured = &id
	engines := make([]*containerState, 0, len(m.engines))
	for _, cs := range m.engines {
		engines = append(engines, cs)
	}
	m.mu.Unlock()
	for _, cs := range engines {
		cs.engine.SetEntrypoint(id)
	}
}

// Close stops every tailer.
func (m *Monitor) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	ids := make([]string, 0, len(m.engines))
	for id := range m.engines {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.ContainerStopped(id)
	}
}
