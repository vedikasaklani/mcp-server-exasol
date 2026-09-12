// Package metrics is the live instrumentation for a long-running warden
// process: counters, gauges, and latency histograms that can be read at
// any moment while traffic is flowing, without stopping or draining
// anything.
//
// It deliberately has no dependencies. A metrics layer that needs a
// scrape library, a push gateway, or a background aggregator is another
// thing that can fail in front of the thing it's supposed to be watching;
// this one is a few atomics and a ring buffer, readable straight out of
// the process that owns them.
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ringSize is how many recent samples a Histogram keeps for percentile
// estimation. Bounded on purpose: a long-running process must not grow
// memory with traffic, and percentiles over the recent window are what
// operational monitoring actually wants — an all-time p99 stops moving
// after a day of uptime and stops telling you anything about now.
const ringSize = 4096

// Counter is a monotonically increasing count.
type Counter struct{ v atomic.Int64 }

func (c *Counter) Inc()         { c.v.Add(1) }
func (c *Counter) Add(n int64)  { c.v.Add(n) }
func (c *Counter) Value() int64 { return c.v.Load() }

// Gauge is a value that goes up and down.
type Gauge struct{ v atomic.Int64 }

func (g *Gauge) Set(n int64)  { g.v.Store(n) }
func (g *Gauge) Add(n int64)  { g.v.Add(n) }
func (g *Gauge) Value() int64 { return g.v.Load() }

// Histogram tracks a duration distribution over a bounded recent window,
// plus all-time count/sum/max.
type Histogram struct {
	mu    sync.Mutex
	ring  [ringSize]time.Duration
	idx   int
	fill  int
	count int64
	sum   time.Duration
	max   time.Duration
}

func (h *Histogram) Observe(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ring[h.idx] = d
	h.idx = (h.idx + 1) % ringSize
	if h.fill < ringSize {
		h.fill++
	}
	h.count++
	h.sum += d
	if d > h.max {
		h.max = d
	}
}

// HistogramSnapshot is a point-in-time read of a Histogram. Percentiles
// are computed over the recent window; Count, Mean and Max are all-time.
type HistogramSnapshot struct {
	Count  int64         `json:"count"`
	Mean   time.Duration `json:"mean_ns"`
	P50    time.Duration `json:"p50_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	Max    time.Duration `json:"max_ns"`
	Window int           `json:"window_samples"`
}

func (h *Histogram) Snapshot() HistogramSnapshot {
	h.mu.Lock()
	samples := make([]time.Duration, h.fill)
	copy(samples, h.ring[:h.fill])
	count, sum, max := h.count, h.sum, h.max
	h.mu.Unlock()

	s := HistogramSnapshot{Count: count, Max: max, Window: len(samples)}
	if count > 0 {
		s.Mean = sum / time.Duration(count)
	}
	if len(samples) == 0 {
		return s
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	s.P50 = quantile(samples, 0.50)
	s.P95 = quantile(samples, 0.95)
	s.P99 = quantile(samples, 0.99)
	return s
}

func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * q)
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// Registry holds every metric a warden process exposes. Metric handles are
// created once at startup and read concurrently forever, so lookups return
// stable pointers rather than copies.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	started    time.Time
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   map[string]*Counter{},
		gauges:     map[string]*Gauge{},
		histograms: map[string]*Histogram{},
		started:    time.Now(),
	}
}

func (r *Registry) Counter(name string) *Counter {
	r.mu.RLock()
	c, ok := r.counters[name]
	r.mu.RUnlock()
	if ok {
		return c
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c = &Counter{}
	r.counters[name] = c
	return c
}

func (r *Registry) Gauge(name string) *Gauge {
	r.mu.RLock()
	g, ok := r.gauges[name]
	r.mu.RUnlock()
	if ok {
		return g
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g = &Gauge{}
	r.gauges[name] = g
	return g
}

func (r *Registry) Histogram(name string) *Histogram {
	r.mu.RLock()
	h, ok := r.histograms[name]
	r.mu.RUnlock()
	if ok {
		return h
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h = &Histogram{}
	r.histograms[name] = h
	return h
}

// Snapshot is a complete point-in-time read of the registry.
type Snapshot struct {
	UptimeSeconds float64                      `json:"uptime_seconds"`
	Counters      map[string]int64             `json:"counters"`
	Gauges        map[string]int64             `json:"gauges"`
	Histograms    map[string]HistogramSnapshot `json:"histograms"`
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s := Snapshot{
		UptimeSeconds: time.Since(r.started).Seconds(),
		Counters:      make(map[string]int64, len(r.counters)),
		Gauges:        make(map[string]int64, len(r.gauges)),
		Histograms:    make(map[string]HistogramSnapshot, len(r.histograms)),
	}
	for k, c := range r.counters {
		s.Counters[k] = c.Value()
	}
	for k, g := range r.gauges {
		s.Gauges[k] = g.Value()
	}
	for k, h := range r.histograms {
		s.Histograms[k] = h.Snapshot()
	}
	return s
}

// WriteJSON writes the snapshot as JSON.
func (r *Registry) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.Snapshot())
}

// WritePrometheus writes the snapshot in Prometheus text exposition
// format, so an existing monitoring stack can scrape this process without
// warden needing to know anything about that stack.
func (r *Registry) WritePrometheus(w io.Writer) error {
	s := r.Snapshot()

	if _, err := fmt.Fprintf(w, "# HELP warden_uptime_seconds Process uptime.\n# TYPE warden_uptime_seconds gauge\nwarden_uptime_seconds %f\n", s.UptimeSeconds); err != nil {
		return err
	}
	for _, k := range sortedKeys(s.Counters) {
		if _, err := fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", k, k, s.Counters[k]); err != nil {
			return err
		}
	}
	for _, k := range sortedKeys(s.Gauges) {
		if _, err := fmt.Fprintf(w, "# TYPE %s gauge\n%s %d\n", k, k, s.Gauges[k]); err != nil {
			return err
		}
	}
	for _, k := range sortedHistKeys(s.Histograms) {
		h := s.Histograms[k]
		if _, err := fmt.Fprintf(w, "# TYPE %s summary\n", k); err != nil {
			return err
		}
		for _, q := range []struct {
			label string
			v     time.Duration
		}{{"0.5", h.P50}, {"0.95", h.P95}, {"0.99", h.P99}} {
			if _, err := fmt.Fprintf(w, "%s{quantile=\"%s\"} %f\n", k, q.label, q.v.Seconds()); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_count %d\n%s_max_seconds %f\n", k, h.Count, k, h.Max.Seconds()); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedHistKeys(m map[string]HistogramSnapshot) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
