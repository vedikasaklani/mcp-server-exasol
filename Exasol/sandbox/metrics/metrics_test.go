package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHistogram_PercentilesOverObservedSamples(t *testing.T) {
	h := &Histogram{}
	for i := 1; i <= 100; i++ {
		h.Observe(time.Duration(i) * time.Millisecond)
	}
	s := h.Snapshot()
	if s.Count != 100 {
		t.Errorf("Count = %d, want 100", s.Count)
	}
	if s.Max != 100*time.Millisecond {
		t.Errorf("Max = %v, want 100ms", s.Max)
	}
	if s.P50 < 45*time.Millisecond || s.P50 > 55*time.Millisecond {
		t.Errorf("P50 = %v, want ~50ms", s.P50)
	}
	if s.P99 < 95*time.Millisecond {
		t.Errorf("P99 = %v, want >=95ms", s.P99)
	}
	if s.Mean < 45*time.Millisecond || s.Mean > 55*time.Millisecond {
		t.Errorf("Mean = %v, want ~50ms", s.Mean)
	}
}

func TestHistogram_WindowIsBoundedButCountIsAllTime(t *testing.T) {
	h := &Histogram{}
	total := ringSize + 500
	for i := 0; i < total; i++ {
		h.Observe(time.Millisecond)
	}
	s := h.Snapshot()
	if s.Count != int64(total) {
		t.Errorf("Count = %d, want all-time %d", s.Count, total)
	}
	if s.Window != ringSize {
		t.Errorf("Window = %d, want it capped at %d — a long-running process must not grow memory with traffic", s.Window, ringSize)
	}
}

func TestHistogram_EmptySnapshotIsSafe(t *testing.T) {
	s := (&Histogram{}).Snapshot()
	if s.Count != 0 || s.P50 != 0 || s.Mean != 0 {
		t.Fatalf("empty histogram must produce a zero snapshot, got %+v", s)
	}
}

func TestRegistry_ReturnsStableHandles(t *testing.T) {
	r := NewRegistry()
	if r.Counter("a") != r.Counter("a") {
		t.Errorf("Counter must return the same handle for the same name")
	}
	if r.Gauge("g") != r.Gauge("g") {
		t.Errorf("Gauge must return the same handle for the same name")
	}
	if r.Histogram("h") != r.Histogram("h") {
		t.Errorf("Histogram must return the same handle for the same name")
	}
}

func TestRegistry_SnapshotReflectsValues(t *testing.T) {
	r := NewRegistry()
	r.Counter("reqs").Add(7)
	r.Gauge("idle").Set(3)
	r.Histogram("lat").Observe(5 * time.Millisecond)

	s := r.Snapshot()
	if s.Counters["reqs"] != 7 {
		t.Errorf("counter = %d, want 7", s.Counters["reqs"])
	}
	if s.Gauges["idle"] != 3 {
		t.Errorf("gauge = %d, want 3", s.Gauges["idle"])
	}
	if s.Histograms["lat"].Count != 1 {
		t.Errorf("histogram count = %d, want 1", s.Histograms["lat"].Count)
	}
	if s.UptimeSeconds < 0 {
		t.Errorf("uptime must be non-negative")
	}
}

func TestRegistry_ConcurrentUseIsSafe(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Counter("c").Inc()
				r.Gauge("g").Add(1)
				r.Histogram("h").Observe(time.Microsecond)
				_ = r.Snapshot() // readers race writers by design here
			}
		}()
	}
	wg.Wait()
	if got := r.Counter("c").Value(); got != 16*200 {
		t.Fatalf("counter = %d, want %d", got, 16*200)
	}
}

func TestWritePrometheus_EmitsScrapeableText(t *testing.T) {
	r := NewRegistry()
	r.Counter("warden_requests_total").Add(5)
	r.Gauge("warden_pool_idle").Set(2)
	r.Histogram("warden_request_seconds").Observe(10 * time.Millisecond)

	var sb strings.Builder
	if err := r.WritePrometheus(&sb); err != nil {
		t.Fatalf("WritePrometheus: %v", err)
	}
	out := sb.String()
	for _, want := range []string{
		"# TYPE warden_requests_total counter",
		"warden_requests_total 5",
		"# TYPE warden_pool_idle gauge",
		"warden_pool_idle 2",
		"warden_request_seconds{quantile=\"0.99\"}",
		"warden_request_seconds_count 1",
		"warden_uptime_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prometheus output missing %q\ngot:\n%s", want, out)
		}
	}
}

func TestWriteJSON_ProducesValidSnapshot(t *testing.T) {
	r := NewRegistry()
	r.Counter("x").Inc()
	var sb strings.Builder
	if err := r.WriteJSON(&sb); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(sb.String(), "\"counters\"") {
		t.Fatalf("unexpected JSON: %s", sb.String())
	}
}
