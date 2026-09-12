package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTrace appends runsc-shaped JSON log lines to a container's trace
// file, exercising the real parse path rather than injecting events.
func writeTrace(t *testing.T, dir string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "runsc.log.boot"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, body := range lines {
		b, _ := json.Marshal(map[string]string{
			"msg":  "strace.go:600] " + body,
			"time": time.Now().UTC().Format(time.RFC3339Nano),
		})
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMonitor_EndToEndFromTraceFileToPosture(t *testing.T) {
	root := t.TempDir()
	locate := func(id string) (string, bool) { return filepath.Join(root, id, "trace"), true }

	mon := NewMonitor(MonitorConfig{
		Baseline: BaselineFromProfile(benignProfile()),
		Locate:   locate,
	})
	defer mon.Close()

	mon.ContainerStarted("c1")
	dir, _ := locate("c1")

	// One clean request.
	mon.RequestStarted("c1", "r1", "read_file",
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/data/a.txt"}}}`))
	writeTrace(t, dir,
		`[   1:   1] node X openat(AT_FDCWD /, 0x1 /srv/data/a.txt, O_RDONLY|0x0, 0o0) = 7 (0x7) (12µs)`,
		`[   1:   1] node X read(0x7, 0x100, 0x1000) = 512 (0x200) (8µs)`,
	)
	waitFor(t, 3*time.Second, "clean request events", func() bool {
		return mon.Aggregate().Totals.FileReadBytes >= 512
	})
	mon.RequestFinished("c1", "r1", Outcome{ResponseBytes: 540, Latency: 3 * time.Millisecond}, nil)

	if p := mon.Score().Posture; p != TierTrusted {
		t.Fatalf("a clean request must leave the posture trusted, got %q (%s)", p, mon.Score().PostureReason)
	}

	// Now a request that reads a credential store outside the profile and
	// pushes it out a socket.
	mon.RequestStarted("c1", "r2", "read_file",
		[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/data/b.txt"}}}`))
	writeTrace(t, dir,
		`[   1:   1] node X openat(AT_FDCWD /, 0x1 /home/neal/.aws/credentials, O_RDONLY|0x0, 0o0) = 8 (0x8) (14µs)`,
		`[   1:   1] node X read(0x8, 0x100, 0x1000) = 620 (0x26c) (9µs)`,
		`[   1:   1] node X socket(0x2, 0x1, 0x0) = 9 (0x9) (5µs)`,
		`[   1:   1] node X connect(0x9 socket:[2], 0x7ffd {Family: AF_INET, Addr: 198.51.100.7, Port: 443}, 0x10) = 0 (0x0) (300µs)`,
		`[   1:   1] node X sendto(0x9, 0x100, 0x26c, 0x0, 0x0, 0x0) = 620 (0x26c) (40µs)`,
	)
	waitFor(t, 3*time.Second, "exfiltration events", func() bool {
		return mon.Aggregate().Totals.NetWriteBytes >= 620
	})
	mon.RequestFinished("c1", "r2", Outcome{ResponseBytes: 40, Latency: 4 * time.Millisecond}, nil)

	sc := mon.Score()
	if sc.Posture != TierQuarantine {
		t.Fatalf("posture = %q (%s); a credential read outside the profile followed by egress must quarantine",
			sc.Posture, sc.PostureReason)
	}
	fs := mon.Findings()
	for _, want := range []string{"read-then-egress", "path-drift", "network-drift", "credential-access"} {
		if !hasDetector(fs, want) {
			t.Errorf("%s did not fire; got %v", want, keys(fs))
		}
	}

	agg := mon.Aggregate()
	if agg.Requests != 2 {
		t.Errorf("requests = %d, want 2", agg.Requests)
	}
	if agg.Totals.Dials["198.51.100.7:443"] == 0 {
		t.Errorf("destination not recorded: %v", agg.Totals.Dials)
	}
	if agg.Stats.EventsIngested == 0 {
		t.Errorf("pipeline reported no events despite a populated trace file")
	}
}

func TestMonitor_FindingsSurviveContainerRetirement(t *testing.T) {
	// A pool retires and replaces containers constantly. A detection that
	// vanished when its container did would make quarantine unobservable
	// exactly when it matters.
	root := t.TempDir()
	locate := func(id string) (string, bool) { return filepath.Join(root, id, "trace"), true }
	mon := NewMonitor(MonitorConfig{Baseline: BaselineFromProfile(benignProfile()), Locate: locate})
	defer mon.Close()

	mon.ContainerStarted("c1")
	dir, _ := locate("c1")
	mon.RequestStarted("c1", "r1", "read_file", nil)
	writeTrace(t, dir,
		`[   1:   1] node X openat(AT_FDCWD /, 0x1 /etc/shadow, O_RDONLY|0x0, 0o0) = 4 (0x4) (11µs)`,
		`[   1:   1] node X read(0x4, 0x100, 0x1000) = 900 (0x384) (7µs)`,
	)
	waitFor(t, 3*time.Second, "events", func() bool { return mon.Aggregate().Totals.FileReadBytes >= 900 })
	mon.RequestFinished("c1", "r1", Outcome{ResponseBytes: 10, Latency: time.Millisecond}, nil)
	mon.Evaluate()

	before := len(mon.Findings())
	if before == 0 {
		t.Fatalf("expected findings before retirement")
	}

	mon.ContainerStopped("c1")
	mon.ContainerStarted("c2")

	if got := len(mon.Findings()); got < before {
		t.Fatalf("findings dropped from %d to %d after the container was retired", before, got)
	}
	if !hasDetector(mon.Findings(), "credential-access") {
		t.Fatalf("the detection must outlive its container: %v", keys(mon.Findings()))
	}
	views := mon.Containers()
	if len(views) != 2 {
		t.Fatalf("expected both the retired and the live container to be listed, got %d", len(views))
	}
}

func TestMonitor_ReportsBlindnessWhenTracingIsOff(t *testing.T) {
	mon := NewMonitor(MonitorConfig{
		Baseline: BaselineFromProfile(benignProfile()),
		Locate:   func(string) (string, bool) { return "", false },
	})
	defer mon.Close()
	mon.ContainerStarted("c1")
	mon.RequestStarted("c1", "r1", "read_file", nil)
	mon.RequestFinished("c1", "r1", Outcome{ResponseBytes: 10, Latency: time.Millisecond}, nil)

	sc := mon.Score()
	if sc.AnalysisHealthy {
		t.Fatalf("with tracing off the monitor must not claim healthy analysis")
	}
	if sc.Posture != TierDegraded {
		t.Fatalf("posture = %q; a server nobody is watching is not a trusted server", sc.Posture)
	}
}

func TestMonitor_ConcurrentContainersDoNotBlendAttribution(t *testing.T) {
	root := t.TempDir()
	locate := func(id string) (string, bool) { return filepath.Join(root, id, "trace"), true }
	mon := NewMonitor(MonitorConfig{Baseline: BaselineFromProfile(benignProfile()), Locate: locate})
	defer mon.Close()

	for _, id := range []string{"c1", "c2"} {
		mon.ContainerStarted(id)
	}
	// Both containers serve at the same time; each is independently
	// serialized, which is what §6.3 actually guarantees.
	mon.RequestStarted("c1", "r1", "read_file", nil)
	mon.RequestStarted("c2", "r2", "read_file", nil)

	d1, _ := locate("c1")
	d2, _ := locate("c2")
	writeTrace(t, d1, `[   1:   1] node X openat(AT_FDCWD /, 0x1 /srv/data/one.txt, O_RDONLY|0x0, 0o0) = 3 (0x3) (9µs)`)
	writeTrace(t, d2, `[   1:   1] node X openat(AT_FDCWD /, 0x1 /srv/data/two.txt, O_RDONLY|0x0, 0o0) = 3 (0x3) (9µs)`)
	waitFor(t, 3*time.Second, "both traces", func() bool {
		return mon.Aggregate().Totals.DistinctPaths() >= 2
	})
	mon.RequestFinished("c1", "r1", Outcome{ResponseBytes: 10, Latency: time.Millisecond}, nil)
	mon.RequestFinished("c2", "r2", Outcome{ResponseBytes: 10, Latency: time.Millisecond}, nil)

	views := mon.Containers()
	byID := map[string]ContainerView{}
	for _, v := range views {
		byID[v.ID] = v
	}
	for _, id := range []string{"c1", "c2"} {
		if byID[id].Requests != 1 {
			t.Errorf("%s served %d requests, want 1 — per-container attribution must not blend", id, byID[id].Requests)
		}
	}
	if got := mon.Aggregate().Requests; got != 2 {
		t.Errorf("aggregate requests = %d, want 2", got)
	}
}

func TestMonitor_ConcurrentIngestAndQueryIsRaceFree(t *testing.T) {
	root := t.TempDir()
	locate := func(id string) (string, bool) { return filepath.Join(root, id, "trace"), true }
	mon := NewMonitor(MonitorConfig{
		Baseline:      BaselineFromProfile(benignProfile()),
		Locate:        locate,
		EvaluateEvery: 5 * time.Millisecond,
	})
	defer mon.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mon.Run(ctx)

	for i := 0; i < 4; i++ {
		mon.ContainerStarted(fmt.Sprintf("c%d", i))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			cid := fmt.Sprintf("c%d", i%4)
			rid := fmt.Sprintf("r%d", i)
			mon.RequestStarted(cid, rid, "read_file", nil)
			dir, _ := locate(cid)
			if i%20 == 0 {
				writeTrace(t, dir, `[   1:   1] node X openat(AT_FDCWD /, 0x1 /srv/data/x, O_RDONLY|0x0, 0o0) = 3 (0x3) (9µs)`)
			}
			mon.RequestFinished(cid, rid, Outcome{ResponseBytes: 10, Latency: time.Millisecond}, nil)
		}
	}()
	for {
		select {
		case <-done:
			if got := mon.Aggregate().Requests; got != 200 {
				t.Fatalf("requests = %d, want 200", got)
			}
			return
		default:
			_ = mon.Findings()
			_ = mon.Score()
			_ = mon.Aggregate()
			_ = mon.Containers()
		}
	}
}
