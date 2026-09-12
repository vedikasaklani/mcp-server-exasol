package analyze

import (
	"math"
	"sort"
	"time"
)

// Snapshot is a consistent read of session state, taken under the
// engine's lock and safe to hand to detectors and HTTP handlers. Windows
// inside it are copies: a detector cannot corrupt live accounting, and a
// slow dashboard render cannot block ingestion.
type Snapshot struct {
	TakenAt   time.Time `json:"taken_at"`
	StartedAt time.Time `json:"started_at"`
	Uptime    float64   `json:"uptime_seconds"`

	Baseline *Baseline `json:"baseline"`

	// Totals is the whole session: every window, open, closed, evicted,
	// and idle, folded together.
	Totals *Window `json:"totals"`
	// Idle is everything observed while no request was in flight.
	Idle *Window `json:"idle"`
	// Recent holds the retained completed request windows, oldest first.
	Recent []*Window `json:"recent"`
	// Open is the in-flight window, if any.
	Open *Window `json:"open,omitempty"`

	Requests     int `json:"requests"`
	Failures     int `json:"failures"`
	Denials      int `json:"denials"`
	Unattributed int `json:"unattributed_events"`

	Latency     Percentiles            `json:"latency"`
	ToolLatency map[string]Percentiles `json:"tool_latency"`

	ManifestHash string             `json:"manifest_hash,omitempty"`
	Entrypoint   EntrypointIdentity `json:"entrypoint"`

	// IdleBursts are the start times of distinct clusters of idle
	// activity. Beacon detection reads the intervals between them.
	IdleBursts []time.Time `json:"-"`

	// Stats describes the health of the observation pipeline itself.
	Stats PipelineStats `json:"pipeline"`
}

// PipelineStats reports on the monitoring path, not the monitored
// process. A detection system that cannot say whether it is currently
// seeing everything is a detection system whose silence means nothing.
type PipelineStats struct {
	EventsIngested int64     `json:"events_ingested"`
	EventsDropped  int64     `json:"events_dropped"`
	LastEventAt    time.Time `json:"last_event_at"`
	LinesRead      int64     `json:"lines_read"`
	BytesRead      int64     `json:"bytes_read"`
	LogTruncations int64     `json:"log_truncations"`
	TracingEnabled bool      `json:"tracing_enabled"`
}

// Percentiles summarises a latency sample set.
type Percentiles struct {
	Count int           `json:"count"`
	P50   time.Duration `json:"p50_ns"`
	P95   time.Duration `json:"p95_ns"`
	P99   time.Duration `json:"p99_ns"`
	Max   time.Duration `json:"max_ns"`
	Mean  time.Duration `json:"mean_ns"`
}

func percentiles(samples []time.Duration) Percentiles {
	if len(samples) == 0 {
		return Percentiles{}
	}
	s := append([]time.Duration(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var total time.Duration
	for _, v := range s {
		total += v
	}
	at := func(q float64) time.Duration {
		idx := int(math.Ceil(q*float64(len(s)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(s) {
			idx = len(s) - 1
		}
		return s[idx]
	}
	return Percentiles{
		Count: len(s),
		P50:   at(0.50),
		P95:   at(0.95),
		P99:   at(0.99),
		Max:   s[len(s)-1],
		Mean:  total / time.Duration(len(s)),
	}
}

// copyWindow deep-copies the parts of a window a detector may read.
func copyWindow(w *Window) *Window {
	if w == nil {
		return nil
	}
	cp := *w
	cp.Syscalls = make(map[string]int, len(w.Syscalls))
	for k, v := range w.Syscalls {
		cp.Syscalls[k] = v
	}
	cp.Errnos = make(map[string]int, len(w.Errnos))
	for k, v := range w.Errnos {
		cp.Errnos[k] = v
	}
	cp.Paths = make(map[string]*Access, len(w.Paths))
	for k, v := range w.Paths {
		a := *v
		cp.Paths[k] = &a
	}
	cp.Dials = make(map[string]int, len(w.Dials))
	for k, v := range w.Dials {
		cp.Dials[k] = v
	}
	cp.Execs = append([]string(nil), w.Execs...)
	cp.SensitiveReads = append([]string(nil), w.SensitiveReads...)
	cp.Denied = append([]string(nil), w.Denied...)
	cp.SecretHits = append([]string(nil), w.SecretHits...)
	cp.InjectionHits = append([]string(nil), w.InjectionHits...)
	cp.Args = make(map[string]string, len(w.Args))
	for k, v := range w.Args {
		cp.Args[k] = v
	}
	return &cp
}

// Snapshot takes a consistent read of the session.
func (e *Engine) Snapshot() *Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshotLocked()
}

func (e *Engine) snapshotLocked() *Snapshot {
	now := e.now()

	// Totals must include everything still retained, not only what has
	// been evicted into the running aggregate, or a short-lived session
	// would report almost nothing.
	totals := newWindow("", e.started)
	totals.merge(e.totals)
	for _, w := range e.pending {
		totals.merge(w)
	}
	totals.merge(e.idle)
	if e.open != nil {
		totals.merge(e.open)
	}

	recent := make([]*Window, 0, len(e.pending))
	for _, w := range e.pending {
		recent = append(recent, copyWindow(w))
	}

	toolLat := make(map[string]Percentiles, len(e.toolLatency))
	for name, s := range e.toolLatency {
		toolLat[name] = percentiles(s)
	}

	return &Snapshot{
		TakenAt:      now,
		StartedAt:    e.started,
		Uptime:       now.Sub(e.started).Seconds(),
		Baseline:     e.baseline,
		Totals:       totals,
		Idle:         copyWindow(e.idle),
		Recent:       recent,
		Open:         copyWindow(e.open),
		Requests:     e.requests,
		Failures:     e.failures,
		Denials:      e.denials,
		Unattributed: e.unattributed,
		Latency:      percentiles(e.latencies),
		ToolLatency:  toolLat,
		ManifestHash: e.manifestHash,
		Entrypoint:   e.entrypoint,
		IdleBursts:   append([]time.Time(nil), e.idleBursts...),
		Stats:        e.stats,
	}
}

// CompletedRequests returns the retained windows that represent finished
// *caller* tool calls: not the idle window, and not proxy-initiated
// handshakes. This is the set every statistical baseline is computed
// over, so it must contain only comparable things.
func (s *Snapshot) CompletedRequests() []*Window {
	out := make([]*Window, 0, len(s.Recent))
	for _, w := range s.Recent {
		if !w.Idle && !w.Synthetic && w.Closed {
			out = append(out, w)
		}
	}
	return out
}

// AllWindows returns every retained window including synthetic and idle
// ones. Detectors asserting facts about observed behaviour — rather than
// comparing against a baseline — use this: a credential read followed by
// egress is just as real during the handshake as during a tool call.
func (s *Snapshot) AllWindows() []*Window {
	out := make([]*Window, 0, len(s.Recent)+2)
	out = append(out, s.Recent...)
	if s.Idle != nil {
		out = append(out, s.Idle)
	}
	if s.Open != nil {
		out = append(out, s.Open)
	}
	return out
}

// Warm reports whether enough requests have completed for the
// statistical detectors to have a meaningful baseline. Before this is
// true they must stay silent rather than compare a measurement against
// two data points.
func (s *Snapshot) Warm() bool {
	need := s.Baseline.WarmupRequests
	if need <= 0 {
		need = 20
	}
	return s.Requests >= need
}

// MedianDistinctPaths is the typical per-request fan-out across retained
// windows — the reference the fan-out detector measures against.
func (s *Snapshot) MedianDistinctPaths() float64 {
	var vals []float64
	for _, w := range s.CompletedRequests() {
		vals = append(vals, float64(w.DistinctPaths()))
	}
	return median(vals)
}

// MedianFileReadBytes is the typical per-request read volume.
func (s *Snapshot) MedianFileReadBytes() float64 {
	var vals []float64
	for _, w := range s.CompletedRequests() {
		vals = append(vals, float64(w.FileReadBytes))
	}
	return median(vals)
}

func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// madScore returns a robust outlier score for v against vals: the number
// of median-absolute-deviations v sits from the median.
//
// MAD rather than standard deviation because a single exfiltration burst
// would inflate a standard deviation enough to hide itself. The estimator
// used to flag an outlier must not be one the outlier can move.
func madScore(v float64, vals []float64) float64 {
	if len(vals) < 4 {
		return 0
	}
	m := median(vals)
	devs := make([]float64, len(vals))
	for i, x := range vals {
		devs[i] = math.Abs(x - m)
	}
	mad := median(devs)
	if mad == 0 {
		// A perfectly consistent history: any deviation at all is
		// notable, but scale it so a one-byte difference is not a crisis.
		if v == m {
			return 0
		}
		return math.Abs(v-m) / math.Max(1, m)
	}
	return math.Abs(v-m) / (1.4826 * mad)
}
