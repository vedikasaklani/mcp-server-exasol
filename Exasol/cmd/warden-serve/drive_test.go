package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/metrics"
	"mcp-warden/sandbox/runtime/runsc"
)

func TestLoadRequests_ParsesAndSkipsComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "reqs.jsonl")
	os.WriteFile(p, []byte(`
# a comment
{"jsonrpc":"2.0","method":"tools/list","params":{}}

{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x"}}}
`), 0o644)

	got, err := loadRequests(p)
	if err != nil {
		t.Fatalf("loadRequests: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d requests, want 2", len(got))
	}
	if got[0].tool != "tools/list" {
		t.Errorf("request 0 tool = %q", got[0].tool)
	}
	// The tool name for a tools/call is the tool, not the method — it is
	// what per-tool latency and duration budgets key on.
	if got[1].tool != "read_file" {
		t.Errorf("request 1 tool = %q, want read_file", got[1].tool)
	}
	if got[1].body["jsonrpc"] != "2.0" {
		t.Errorf("a missing jsonrpc version must be filled in: %v", got[1].body)
	}
}

func TestLoadRequests_RejectsEmptyAndMalformed(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(empty, []byte("\n# only comments\n"), 0o644)
	if _, err := loadRequests(empty); err == nil {
		t.Errorf("a file with no requests must be an error, not a silent no-op driver")
	}
	bad := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(bad, []byte("{not json}\n"), 0o644)
	if _, err := loadRequests(bad); err == nil {
		t.Errorf("malformed JSON must be reported with its line number")
	}
}

func TestFormatting_HelpersAreStableForTheLiveView(t *testing.T) {
	cases := []struct{ got, want string }{
		{bytesOf(0), "0 B"},
		{bytesOf(1023), "1023 B"},
		{bytesOf(1536), "1.5 KB"},
		{bytesOf(5 << 20), "5.0 MB"},
		{msOf(0), "—"},
		{msOf(500 * time.Microsecond), "500 µs"},
		{msOf(2500 * time.Microsecond), "2.50 ms"},
		{addCommas("1234567"), "1,234,567"},
		{addCommas("42"), "42"},
		{dur(90 * time.Second), "1m30s"},
		{dur(3725 * time.Second), "1h02m05s"},
		{trunc("abcdef", 4), "abc…"},
		{trunc("abc", 8), "abc"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("case %d: got %q, want %q", i, c.got, c.want)
		}
	}
}

func TestBar_MakesASmallNonZeroValueVisible(t *testing.T) {
	// The distinction that matters most on this dashboard is "some bytes
	// left over the network" versus "none". A bar that rounds a small
	// value to empty erases exactly that.
	if got := bar(0, 1000, 10); got != "          " {
		t.Errorf("zero must render empty, got %q", got)
	}
	if got := bar(1, 1_000_000, 10); got == "          " {
		t.Errorf("a tiny non-zero value must still be visible, got %q", got)
	}
	full := bar(1000, 1000, 10)
	if len([]rune(full)) != 10 {
		t.Errorf("a full bar must fill its width exactly, got %q (%d runes)", full, len([]rune(full)))
	}
	if got := bar(500, 0, 10); got != "          " {
		t.Errorf("a zero maximum must not divide by zero, got %q", got)
	}
}

func TestPostureStyle_CoversEveryTier(t *testing.T) {
	for _, tier := range []analyze.Tier{
		analyze.TierTrusted, analyze.TierWatch, analyze.TierDegraded, analyze.TierQuarantine,
	} {
		col, glyph := postureStyle(tier)
		if col == "" || glyph == "" {
			t.Errorf("tier %q has no style", tier)
		}
		// Colour must never be the only channel; the tier name is always
		// printed beside the glyph, and the glyphs differ from each other.
		if glyph == "?" {
			t.Errorf("tier %q fell through to the unknown glyph", tier)
		}
	}
}

func TestTierValue_OrdersWorstHighest(t *testing.T) {
	// Alerting rules threshold on this, so the direction matters.
	if !(tierValue(analyze.TierTrusted) < tierValue(analyze.TierWatch) &&
		tierValue(analyze.TierWatch) < tierValue(analyze.TierDegraded) &&
		tierValue(analyze.TierDegraded) < tierValue(analyze.TierQuarantine)) {
		t.Fatalf("posture tiers must be monotonic with severity")
	}
}

func TestLiveView_RendersEmptyStateWithoutPanicking(t *testing.T) {
	// The first frame is drawn before any container has served anything,
	// and again after the last one has been torn down. Both are states
	// where most of the snapshot is zero values.
	mon := analyze.NewMonitor(analyze.MonitorConfig{
		Baseline: &analyze.Baseline{},
		Locate:   func(string) (string, bool) { return "", false },
	})
	defer mon.Close()

	var buf bytes.Buffer
	v := &liveView{
		srv: &server{
			mon: mon, reg: metrics.NewRegistry(), rt: &runsc.Runtime{},
			target: "node /srv/index.js", session: "sess_test", addr: "127.0.0.1:0",
			poolN: 2, tracing: false,
		},
		interval: time.Second,
		out:      &buf,
	}
	v.draw()

	out := buf.String()
	for _, want := range []string{"warden", "TRUSTED", "REQUESTS", "FINDINGS", "Ctrl-C"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty frame missing %q", want)
		}
	}
	// With tracing off the frame must say so rather than implying a clean
	// session nobody observed.
	if !strings.Contains(out, "analysis OFF") {
		t.Errorf("a frame with tracing off must say so:\n%s", out)
	}
}

func TestLiveView_RendersPopulatedStateAndShrinksCleanly(t *testing.T) {
	mon := analyze.NewMonitor(analyze.MonitorConfig{
		Baseline: &analyze.Baseline{},
		Locate:   func(string) (string, bool) { return "", false },
	})
	defer mon.Close()
	mon.ContainerStarted("sbx_abc123")
	for i := 0; i < 5; i++ {
		id := "r" + string(rune('0'+i))
		mon.RequestStarted("sbx_abc123", id, "read_file", nil)
		mon.RequestFinished("sbx_abc123", id, analyze.Outcome{
			ResponseBytes: 100, Latency: 2 * time.Millisecond, ToolName: "read_file",
		}, nil)
	}

	var buf bytes.Buffer
	v := &liveView{
		srv: &server{
			mon: mon, reg: metrics.NewRegistry(), rt: &runsc.Runtime{},
			target: "node /srv/index.js", session: "s", addr: "127.0.0.1:0", poolN: 1, tracing: true,
		},
		interval: time.Second, out: &buf,
	}
	v.draw()
	tall := v.lastLines
	if tall == 0 {
		t.Fatalf("frame rendered no lines")
	}
	if !strings.Contains(buf.String(), "sbx_abc123") {
		t.Errorf("the live container must be listed")
	}

	// A frame that shrinks must erase its own tail, or the previous
	// frame's text stays on screen forever.
	buf.Reset()
	v.lastLines = tall + 6
	v.draw()
	if got := strings.Count(buf.String(), ansiClearLn); got < tall+6 {
		t.Errorf("a shrinking frame must clear every line it previously used: %d clears for %d lines", got, tall+6)
	}
}
