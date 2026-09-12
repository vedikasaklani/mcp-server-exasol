package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"mcp-warden/sandbox/analyze"
)

// ANSI control sequences. Written directly rather than pulled from a TUI
// library: the whole point of this view is to be a dependency-free thing
// you can run over ssh on a box you are debugging.
const (
	ansiHide    = "\033[?25l"
	ansiShow    = "\033[?25h"
	ansiHome    = "\033[H"
	ansiClear   = "\033[2J"
	ansiClearLn = "\033[K"
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"

	colGood     = "\033[32m"
	colWarning  = "\033[33m"
	colSerious  = "\033[38;5;209m"
	colCritical = "\033[31m"
	colAccent   = "\033[36m"
)

// liveView renders a full-screen terminal dashboard that refreshes until
// the process is interrupted.
//
// A frame is built entirely in memory and written with one syscall, then
// the cursor is sent home rather than the screen being cleared. Clearing
// per frame is what makes a terminal dashboard flicker, and a flickering
// dashboard is one nobody watches for long — which defeats the purpose of
// a view meant to be left running.
type liveView struct {
	srv      *server
	interval time.Duration
	// out is where frames are written. Injectable so the renderer can be
	// exercised in tests: a nil dereference here would crash the daemon
	// that exists to watch something else, which is the one failure this
	// view must not have.
	out io.Writer
	// lastLines is how many lines the previous frame occupied, so a
	// shrinking frame can erase its own tail instead of leaving debris.
	lastLines int
	started   time.Time
	prevReq   int
	prevAt    time.Time
	rate      float64
}

func (v *liveView) writer() io.Writer {
	if v.out != nil {
		return v.out
	}
	return os.Stdout
}

func (v *liveView) run(ctx context.Context) {
	v.started = time.Now()
	v.prevAt = v.started
	fmt.Fprint(v.writer(), ansiHide+ansiClear+ansiHome)
	defer fmt.Fprint(v.writer(), ansiShow+"\n")

	t := time.NewTicker(v.interval)
	defer t.Stop()
	for {
		v.draw()
		select {
		case <-ctx.Done():
			v.draw()
			return
		case <-t.C:
		}
	}
}

func (v *liveView) draw() {
	var b strings.Builder
	b.WriteString(ansiHome)

	snap := v.srv.mon.Aggregate()
	score := v.srv.mon.Score()
	findings := v.srv.mon.Findings()
	stats := v.srv.reg.Snapshot()

	// Requests-per-second over the interval actually elapsed, not a
	// nominal one — a stalled daemon should read as zero, not as its
	// configured tick rate.
	now := time.Now()
	if d := now.Sub(v.prevAt).Seconds(); d > 0.5 {
		v.rate = float64(snap.Requests-v.prevReq) / d
		v.prevReq, v.prevAt = snap.Requests, now
	}

	lines := 0
	w := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...))
		b.WriteString(ansiClearLn + "\n")
		lines++
	}

	w("%s%swarden%s  %s  %s", ansiBold, colAccent, ansiReset, v.srv.target, dimf("up %s", dur(time.Since(v.started))))
	w("%s", dimf("session %s · pool %d · %s", v.srv.session, v.srv.poolN, v.traceLabel()))
	w("")

	// ---- posture -------------------------------------------------------
	col, glyph := postureStyle(score.Posture)
	w("  %s%s %s%s   %s", col, glyph, strings.ToUpper(string(score.Posture)), ansiReset, score.PostureReason)
	w("  %s", dimf("%d critical · %d high · %d medium · %d low   (%d kernel-attested)",
		score.Critical, score.High, score.Medium, score.Low, score.Deterministic))
	if !score.AnalysisHealthy {
		w("  %s⚠ analysis degraded — an empty findings list below means nothing%s", colSerious, ansiReset)
	}
	if narr := v.srv.mon.Narrative(); len(narr.Points) > 1 {
		// Points[0] is always PostureReason, already shown above; a
		// correlation or residual line beyond that is worth surfacing
		// here, one at a time, as the dashboard's single most important
		// extra sentence.
		w("  %s%s%s", colAccent, trunc(narr.Points[1], 118), ansiReset)
	}
	w("")

	// ---- counters ------------------------------------------------------
	t := snap.Totals
	lat := snap.Latency
	w("  %sREQUESTS%s            %sLATENCY%s              %sSANDBOX%s", ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset)
	w("    served %9s    p50 %11s      syscalls %10s",
		num(snap.Requests), msOf(lat.P50), num(t.SyscallCount()))
	w("    failed %9s    p95 %11s      failed   %10s",
		numWarn(snap.Failures), msOf(lat.P95), num(t.ErrorCount()))
	w("    rate   %9s    p99 %11s      paths    %10s",
		fmt.Sprintf("%.1f/s", v.rate), msOf(lat.P99), num(t.DistinctPaths()))
	w("    denials%9s    max %11s      spawns   %10s",
		numWarn(snap.Denials), msOf(lat.Max), num(t.Forks))
	w("")

	// ---- data flow -----------------------------------------------------
	w("  %sDATA FLOW%s   %s", ansiDim, ansiReset, flowLine(t))
	w("  %sIDLE%s        %s", ansiDim, ansiReset, idleLine(snap))
	w("  %sPIPELINE%s    %s", ansiDim, ansiReset, pipelineLine(snap))
	if len(t.Dials) > 0 {
		w("  %sNETWORK%s     %s", ansiDim, ansiReset, dialsLine(t.Dials))
	}
	w("")

	// ---- findings ------------------------------------------------------
	w("  %sFINDINGS%s", ansiDim, ansiReset)
	if len(findings) == 0 {
		w("    %snone — deterministic detectors silent, trace pipeline healthy%s", ansiDim, ansiReset)
	}
	shown := 0
	for _, f := range findings {
		if shown >= 8 {
			w("    %s… and %d more (curl /findings for the full set)%s", ansiDim, len(findings)-shown, ansiReset)
			break
		}
		sc := severityColor(f.Severity)
		w("    %s%-9s%s %s%-24s%s %s", sc, f.Severity, ansiReset, ansiDim, f.Detector, ansiReset, trunc(f.Title, 46))
		w("              %s%s%s", ansiDim, trunc(f.Detail, 92), ansiReset)
		shown++
	}
	w("")

	// ---- containers ----------------------------------------------------
	w("  %sCONTAINERS%s  %s", ansiDim, ansiReset, dimf("attribution is exact within one, by container across them"))
	for _, c := range v.srv.mon.Containers() {
		state := colGood + "live   " + ansiReset
		if !c.Live {
			state = ansiDim + "retired" + ansiReset
		}
		w("    %-18s %s  %6s req  %4s den  %8s ev  %5s drop  %9s read  %9s out",
			trunc(c.ID, 18), state, num(c.Requests), numWarn(c.Denials),
			num64(c.Events), numWarn64(c.Dropped), bytesOf(c.FileReadBytes), bytesOf(c.NetWriteBytes))
	}
	w("")

	// ---- audit ---------------------------------------------------------
	if v.srv.audit != nil {
		st := v.srv.audit.Stats()
		gap := ""
		if st.Dropped > 0 {
			gap = fmt.Sprintf("  %s%d dropped (recorded as gaps)%s", colSerious, st.Dropped, ansiReset)
		}
		w("  %sAUDIT%s       %s entries · head %s · backlog %s%s",
			ansiDim, ansiReset, num64(st.Written), trunc(st.ChainHead, 26), num64(st.Backlog), gap)
	}
	if pd := stats.Gauges["warden_pool_degraded"]; pd > 0 {
		w("  %sPOOL%s        %sdegraded — running below configured size%s", ansiDim, ansiReset, colSerious, ansiReset)
	}
	w("")
	w("  %shttp://%s/  ·  Ctrl-C to stop (containers destroyed, audit chain closed)%s",
		ansiDim, v.srv.addr, ansiReset)

	// Erase whatever the previous, taller frame left behind.
	for i := lines; i < v.lastLines; i++ {
		b.WriteString(ansiClearLn + "\n")
	}
	v.lastLines = lines
	_, _ = io.WriteString(v.writer(), b.String())
}

// ---- formatting helpers -------------------------------------------------

func postureStyle(t analyze.Tier) (string, string) {
	switch t {
	case analyze.TierTrusted:
		return colGood, "●"
	case analyze.TierWatch:
		return colWarning, "◐"
	case analyze.TierDegraded:
		return colSerious, "◑"
	case analyze.TierQuarantine:
		return colCritical, "■"
	}
	return ansiDim, "?"
}

func severityColor(s analyze.Severity) string {
	switch s {
	case analyze.SeverityCritical:
		return colCritical
	case analyze.SeverityHigh:
		return colSerious
	case analyze.SeverityMedium:
		return colWarning
	}
	return ansiDim
}

// traceLabel states what observation is actually running, including the
// two degraded modes. A dashboard that says "analysis on" while the
// filter it was asked for was silently dropped is lying by omission.
func (v *liveView) traceLabel() string {
	if !v.srv.tracing {
		return "analysis OFF (confinement still enforced)"
	}
	filterDropped, tracingDropped := v.srv.rt.TraceDegraded()
	switch {
	case tracingDropped:
		return "analysis UNAVAILABLE — runsc would not start a traced container"
	case filterDropped:
		return "analysis on (unfiltered: runsc rejected the syscall filter)"
	}
	return "analysis on"
}

// bar renders a proportional bar. Eighth-block characters give sub-cell
// resolution, so a small non-zero value is visibly different from zero —
// which for network egress is the distinction that matters most.
func bar(value, max int64, width int) string {
	if max <= 0 || value <= 0 {
		return strings.Repeat(" ", width)
	}
	eighths := int(float64(value) / float64(max) * float64(width) * 8)
	if eighths < 1 {
		eighths = 1
	}
	full := eighths / 8
	if full > width {
		full = width
	}
	rem := eighths % 8
	out := strings.Repeat("█", full)
	if full < width && rem > 0 {
		out += string([]rune("▏▎▍▌▋▊▉")[rem-1])
		full++
	}
	return out + strings.Repeat(" ", width-full)
}

func flowLine(t *analyze.Window) string {
	max := t.FileReadBytes
	for _, v := range []int64{t.FileWriteBytes, t.NetReadBytes, t.NetWriteBytes} {
		if v > max {
			max = v
		}
	}
	egress := fmt.Sprintf("net out %s%s%s", bar(t.NetWriteBytes, max, 10), " ", bytesOf(t.NetWriteBytes))
	if t.NetWriteBytes > 0 {
		egress = colWarning + egress + ansiReset
	} else {
		egress = ansiDim + egress + ansiReset
	}
	return fmt.Sprintf("file read %s %-9s  file write %s %-9s  %s",
		bar(t.FileReadBytes, max, 10), bytesOf(t.FileReadBytes),
		bar(t.FileWriteBytes, max, 8), bytesOf(t.FileWriteBytes), egress)
}

func idleLine(s *analyze.Snapshot) string {
	out := fmt.Sprintf("%s syscalls · %d bursts · %s egress",
		num(s.Idle.SyscallCount()), len(s.IdleBursts), bytesOf(s.Idle.NetWriteBytes))
	if s.Idle.NetWriteBytes > 0 {
		return colCritical + out + ansiReset
	}
	return ansiDim + out + ansiReset
}

func pipelineLine(s *analyze.Snapshot) string {
	p := s.Stats
	out := fmt.Sprintf("%s events · %s dropped · %s read · %d truncations",
		num64(p.EventsIngested), num64(p.EventsDropped), bytesOf(p.BytesRead), p.LogTruncations)
	if p.EventsDropped > 0 {
		return colSerious + out + ansiReset
	}
	return ansiDim + out + ansiReset
}

func dialsLine(dials map[string]int) string {
	keys := make([]string, 0, len(dials))
	for k := range dials {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return dials[keys[i]] > dials[keys[j]] })
	if len(keys) > 4 {
		keys = keys[:4]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, dials[k]))
	}
	return colWarning + strings.Join(parts, "  ") + ansiReset
}

func dimf(format string, args ...any) string {
	return ansiDim + fmt.Sprintf(format, args...) + ansiReset
}

func num(n int) string { return addCommas(fmt.Sprint(n)) }

func num64(n int64) string { return addCommas(fmt.Sprint(n)) }

func numWarn(n int) string {
	if n > 0 {
		return colCritical + num(n) + ansiReset
	}
	return num(n)
}

func numWarn64(n int64) string {
	if n > 0 {
		return colSerious + num64(n) + ansiReset
	}
	return num64(n)
}

func addCommas(s string) string {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		return "-" + s
	}
	return s
}

func msOf(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.0f µs", float64(d.Nanoseconds())/1e3)
	}
	return fmt.Sprintf("%.2f ms", float64(d.Nanoseconds())/1e6)
}

func bytesOf(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if f < 10 {
		return fmt.Sprintf("%.1f %s", f, units[i])
	}
	return fmt.Sprintf("%.0f %s", f, units[i])
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// trunc shortens a string to n display columns. Length is measured in
// runes, not bytes, so a path with non-ASCII in it does not blow the
// column alignment out.
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// printFinalReport writes the end-of-session summary after the live view
// has torn down. A monitoring run that ends with a cleared screen and no
// record of what it saw would waste everything it just observed.
func printFinalReport(srv *server, score analyze.Score, snap *analyze.Snapshot, findings []analyze.Finding) {
	col, glyph := postureStyle(score.Posture)
	fmt.Printf("\n%s%s session summary%s  %s\n", ansiBold, colAccent, ansiReset, srv.target)
	fmt.Printf("  posture      %s%s %s%s — %s\n", col, glyph, strings.ToUpper(string(score.Posture)), ansiReset, score.PostureReason)
	fmt.Printf("  requests     %s served, %s failed (%.2f%% errors)\n",
		num(snap.Requests), num(snap.Failures), score.Reliability.ErrorRate*100)
	fmt.Printf("  latency      p50 %s · p95 %s · p99 %s · max %s\n",
		msOf(snap.Latency.P50), msOf(snap.Latency.P95), msOf(snap.Latency.P99), msOf(snap.Latency.Max))
	fmt.Printf("  observed     %s syscalls · %s distinct paths · %s spawns\n",
		num(snap.Totals.SyscallCount()), num(snap.Totals.DistinctPaths()), num(snap.Totals.Forks))
	fmt.Printf("  data flow    %s read from disk · %s written · %s out to network\n",
		bytesOf(snap.Totals.FileReadBytes), bytesOf(snap.Totals.FileWriteBytes), bytesOf(snap.Totals.NetWriteBytes))
	fmt.Printf("  pipeline     %s events ingested, %s dropped\n",
		num64(snap.Stats.EventsIngested), num64(snap.Stats.EventsDropped))

	if len(findings) == 0 {
		fmt.Printf("  findings     none\n")
	} else {
		fmt.Printf("  findings     %d (%d kernel-attested)\n", len(findings), score.Deterministic)
		for _, f := range findings {
			sc := severityColor(f.Severity)
			fmt.Printf("    %s%-9s%s %s/%s  %s ×%d\n", sc, f.Severity, ansiReset, f.Detector, f.Confidence, f.Title, f.Count)
			fmt.Printf("               %s%s%s\n", ansiDim, f.Detail, ansiReset)
			for _, e := range f.Evidence {
				fmt.Printf("               %s· %s%s\n", ansiDim, e, ansiReset)
			}
		}
	}

	if narr := srv.mon.Narrative(); len(narr.Points) > 1 {
		fmt.Printf("\n  %scorrelated summary%s\n", ansiBold, ansiReset)
		for _, p := range narr.Points[1:] {
			fmt.Printf("    %s· %s%s\n", ansiDim, p, ansiReset)
		}
	}
}
