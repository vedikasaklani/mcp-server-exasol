package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/audit"
)

const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiHide    = "\033[?25l"
	ansiShow    = "\033[?25h"
	ansiClear   = "\033[2J"
	ansiHome    = "\033[H"
	ansiClearLn = "\033[K"

	colGood     = "\033[32m"
	colWarning  = "\033[33m"
	colSerious  = "\033[38;5;209m"
	colCritical = "\033[31m"
	colAccent   = "\033[36m"
)

func banner() {
	fmt.Printf("\n%s%smcp-warden console%s  %szero-trust sandbox for untrusted MCP servers%s\n\n",
		ansiBold, colAccent, ansiReset, ansiDim, ansiReset)
}

func prompt(s *session) string {
	if s == nil {
		return fmt.Sprintf("%swarden%s> ", colAccent, ansiReset)
	}
	return fmt.Sprintf("%swarden%s:%s%s%s> ", colAccent, ansiReset, ansiBold, toolNameOf(s.source), ansiReset)
}

func step(format string, args ...any) {
	fmt.Printf("%s%s▶ %s%s\n", ansiBold, colAccent, fmt.Sprintf(format, args...), ansiReset)
}

func ok(format string, args ...any) {
	fmt.Printf("%s✓%s%s\n", colGood, fmt.Sprintf(format, args...), ansiReset)
}

func warn(format string, args ...any) {
	fmt.Printf("%s%s⚠ %s%s\n", ansiBold, colWarning, fmt.Sprintf(format, args...), ansiReset)
}

func fail(format string, args ...any) {
	fmt.Printf("%s✗ %s%s\n", colCritical, fmt.Sprintf(format, args...), ansiReset)
}

func detail(format string, args ...any) {
	fmt.Printf("  %s%s%s\n", ansiDim, fmt.Sprintf(format, args...), ansiReset)
}

func printHelp() {
	fmt.Printf(`%sCOMMANDS%s
  %sload%s <source> [args]   fetch, profile, confine and start a server
                           npm:<pkg>        install a published npm package
                           <git-url>        clone a repository and build it
                           path:<dir>       use a local directory
                           cmd:<argv>       run an already-installed command
  %sservers%s                ready-made, well-known open-source servers to load
  %sset%s [key value]        show or change settings used by the next load
                           pool · network · analyze · rollup · timeout · learn-timeout · write-path
                           sast · storage · exasol-api

  %stools%s                  list the tools the loaded server advertises
  %scall%s <tool> [json]     invoke a tool through the sandbox
  %sraw%s <json>             send one raw JSON-RPC line

  %sscan%s                   run every detector now; posture, correlations, findings
  %sstatus%s                 posture, counters, latency, pipeline health
  %swatch%s [interval]       live refreshing view (press Enter to return)
  %sfindings%s               the current finding list, most severe first
  %scontainers%s             per-container drill-down
  %sprofile%s                the capability profile being enforced
  %saudit%s [n|verify]       tail the hash-chained audit log, or verify it

  %srescan%s                 re-run SAST now against the loaded source
  %sreputation%s             discovery, trust score and audit trail from Exasol
                           (also: %sscore%s)

  %sstop%s                   destroy the containers, print a session report
  %squit%s                   stop and exit

%sNOTES%s
  %sFetching and building a server runs unconfined, as root. Only the server
  process itself is sandboxed. Profiles are auto-approved by this console,
  which is the one thing §3.2 says not to do silently — `+"`profile`"+` shows you
  exactly what was approved.%s

`,
		ansiBold, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		colAccent, ansiReset, colAccent, ansiReset, colAccent, ansiReset,
		ansiBold, ansiReset, ansiDim, ansiReset)
}

// curated is a short list of well-known, open-source MCP servers that are
// safe starting points — all published by the Model Context Protocol
// project itself. They are suggestions, not a trust assertion: the whole
// point of this tool is that a server does not have to be trusted to be
// run, and `scan` tells you what any of them actually did.
var curated = []struct {
	alias string
	spec  string
	args  []string
	note  string
}{
	{"everything", "npm:@modelcontextprotocol/server-everything", nil,
		"reference server exercising tools, prompts, resources — the best one to demo with"},
	{"memory", "npm:@modelcontextprotocol/server-memory", nil,
		"knowledge-graph memory; writes to a local store"},
	{"filesystem", "npm:@modelcontextprotocol/server-filesystem", []string{"/tmp/warden-demo"},
		"file access restricted to the directories given as arguments"},
	{"thinking", "npm:@modelcontextprotocol/server-sequential-thinking", nil,
		"structured reasoning steps; no filesystem or network use"},
}

func lookupAlias(name string) (string, []string, bool) {
	for _, c := range curated {
		if c.alias == name {
			return c.spec, c.args, true
		}
	}
	return "", nil, false
}

func printServers() {
	fmt.Printf("\n  %sready-made servers%s — type `load <name>`\n", ansiBold, ansiReset)
	for _, c := range curated {
		fmt.Printf("    %s%-12s%s %s\n", colAccent, c.alias, ansiReset, c.note)
		fmt.Printf("      %s%s%s\n", ansiDim, c.spec+" "+strings.Join(c.args, " "), ansiReset)
	}
	fmt.Printf("\n  %sanything else works too: a git URL, path:<dir>, npm:<pkg>, or cmd:<argv>%s\n\n", ansiDim, ansiReset)
}

func rollupNote(depth int) string {
	if depth == 0 {
		return ansiDim + "(exact paths — most precise, most mounts)" + ansiReset
	}
	return ansiDim + "(grants directories at this depth — fewer mounts, broader access)" + ansiReset
}

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

func printPosture(score analyze.Score) {
	col, glyph := postureStyle(score.Posture)
	fmt.Printf("  %s%s %s%s   %s\n", col, glyph, strings.ToUpper(string(score.Posture)), ansiReset, score.PostureReason)
	fmt.Printf("  %s%d critical · %d high · %d medium · %d low   (%d kernel-attested)%s\n",
		ansiDim, score.Critical, score.High, score.Medium, score.Low, score.Deterministic, ansiReset)
	if !score.AnalysisHealthy {
		fmt.Printf("  %s⚠ analysis degraded — an empty findings list means nothing right now%s\n", colSerious, ansiReset)
	}
}

func printCounters(snap *analyze.Snapshot, score analyze.Score) {
	t := snap.Totals
	lat := snap.Latency
	fmt.Printf("  %sREQUESTS%s            %sLATENCY%s              %sSANDBOX%s\n",
		ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset)
	fmt.Printf("    served %9s    p50 %11s      syscalls %10s\n", num(snap.Requests), msOf(lat.P50), num(t.SyscallCount()))
	fmt.Printf("    failed %9s    p95 %11s      failed   %10s\n", num(snap.Failures), msOf(lat.P95), num(t.ErrorCount()))
	fmt.Printf("    denials%9s    p99 %11s      paths    %10s\n", num(snap.Denials), msOf(lat.P99), num(t.DistinctPaths()))
	fmt.Println()
	fmt.Printf("  %sDATA FLOW%s   read %s · wrote %s · %snet out %s%s\n",
		ansiDim, ansiReset, bytesOf(t.FileReadBytes), bytesOf(t.FileWriteBytes),
		egressColor(t.NetWriteBytes), bytesOf(t.NetWriteBytes), ansiReset)
	fmt.Printf("  %sIDLE%s        %s syscalls · %d bursts · %s egress\n",
		ansiDim, ansiReset, num(snap.Idle.SyscallCount()), len(snap.IdleBursts), bytesOf(snap.Idle.NetWriteBytes))
	fmt.Printf("  %sPIPELINE%s    %s events · %s dropped%s\n",
		ansiDim, ansiReset, num64(snap.Stats.EventsIngested), num64(snap.Stats.EventsDropped),
		tracingNote(snap.Stats.TracingEnabled))
	if len(t.Dials) > 0 {
		fmt.Printf("  %sNETWORK%s     %s%s%s\n", ansiDim, ansiReset, colWarning, dialsLine(t.Dials), ansiReset)
	}
}

func tracingNote(on bool) string {
	if on {
		return ""
	}
	return colSerious + "  (tracing off — confinement still enforced)" + ansiReset
}

func egressColor(n int64) string {
	if n > 0 {
		return colWarning
	}
	return ansiDim
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
	return strings.Join(parts, "  ")
}

func printNarrative(n analyze.Narrative) {
	fmt.Printf("  %sSUMMARY%s  %s\n", ansiDim, ansiReset, n.Headline)
	for _, p := range n.Points {
		fmt.Printf("    %s· %s%s\n", ansiDim, wrap(p, 96, "      "), ansiReset)
	}
}

func printFindings(findings []analyze.Finding, limit int) {
	if len(findings) == 0 {
		fmt.Printf("  %sFINDINGS%s\n    %snone — deterministic detectors silent, trace pipeline healthy%s\n",
			ansiDim, ansiReset, ansiDim, ansiReset)
		return
	}
	fmt.Printf("  %sFINDINGS (%d)%s\n", ansiDim, len(findings), ansiReset)
	for i, f := range findings {
		if i >= limit {
			fmt.Printf("    %s… and %d more%s\n", ansiDim, len(findings)-i, ansiReset)
			break
		}
		sc := severityColor(f.Severity)
		fmt.Printf("    %s%-9s%s %s%s/%s%s  %s ×%d\n",
			sc, f.Severity, ansiReset, ansiDim, f.Detector, f.Confidence, ansiReset, f.Title, f.Count)
		fmt.Printf("      %s%s%s\n", ansiDim, wrap(f.Detail, 92, "      "), ansiReset)
		for _, e := range f.Evidence {
			fmt.Printf("      %s· %s%s\n", ansiDim, trunc(e, 92), ansiReset)
		}
	}
}

func printAuditEntry(e audit.Entry) {
	ts := e.Timestamp.Format("15:04:05.000")
	switch e.Kind {
	case audit.KindExecution:
		x := e.Execution
		line := fmt.Sprintf("    %s%s%s  exec      %-20s %-8s %5dms", ansiDim, ts, ansiReset, trunc(x.ToolName, 20), x.Status, x.LatencyMS)
		if s := e.Sandbox; s != nil {
			line += fmt.Sprintf("  %ssyscalls=%-6d paths=%-4d read=%-8d net-out=%d%s",
				ansiDim, s.SyscallCount, s.DistinctPaths, s.FileReadBytes, s.NetWriteBytes, ansiReset)
		}
		fmt.Println(line)
	case audit.KindFinding:
		a := e.Analysis
		fmt.Printf("    %s%s%s  %sFINDING%s   [%s/%s] %s\n", ansiDim, ts, ansiReset,
			severityColor(analyze.Severity(a.Severity)), ansiReset, a.Severity, a.Confidence, a.Title)
	case audit.KindLifecycle:
		l := e.Lifecycle
		fmt.Printf("    %s%s  lifecycle %s %s %s%s\n", ansiDim, ts, l.Event, trunc(l.ContainerID, 18), trunc(l.Detail, 50), ansiReset)
	case audit.KindCheckpoint:
		fmt.Printf("    %s%s  checkpoint %d entries, head %s%s\n", ansiDim, ts, e.Checkpoint.Entries, trunc(e.Checkpoint.ChainHead, 24), ansiReset)
	case audit.KindGap:
		fmt.Printf("    %s%s  GAP       %d entries lost: %s%s\n", colSerious, ts, e.Gap.Lost, e.Gap.Reason, ansiReset)
	}
}

// drawWatchFrame renders one frame of the live view, cursor-home rather
// than clear-screen so the view does not flicker.
func (c *console) drawWatchFrame() {
	var b strings.Builder
	b.WriteString(ansiHome)

	snap := c.sess.mon.Aggregate()
	score := c.sess.mon.Score()
	findings := c.sess.mon.Findings()

	w := func(format string, args ...any) {
		b.WriteString(fmt.Sprintf(format, args...) + ansiClearLn + "\n")
	}

	w("%s%smcp-warden%s  %s  %s", ansiBold, colAccent, ansiReset, toolNameOf(c.sess.source),
		fmt.Sprintf("%sup %s · pool %d%s", ansiDim, dur(time.Since(c.sess.started)), c.sess.poolN, ansiReset))
	w("")

	col, glyph := postureStyle(score.Posture)
	w("  %s%s %s%s   %s", col, glyph, strings.ToUpper(string(score.Posture)), ansiReset, score.PostureReason)
	w("  %s%d critical · %d high · %d medium · %d low   (%d kernel-attested)%s",
		ansiDim, score.Critical, score.High, score.Medium, score.Low, score.Deterministic, ansiReset)
	w("")

	t := snap.Totals
	lat := snap.Latency
	w("  %sREQUESTS%s            %sLATENCY%s              %sSANDBOX%s",
		ansiDim, ansiReset, ansiDim, ansiReset, ansiDim, ansiReset)
	w("    served %9s    p50 %11s      syscalls %10s", num(snap.Requests), msOf(lat.P50), num(t.SyscallCount()))
	w("    failed %9s    p95 %11s      failed   %10s", num(snap.Failures), msOf(lat.P95), num(t.ErrorCount()))
	w("    denials%9s    p99 %11s      paths    %10s", num(snap.Denials), msOf(lat.P99), num(t.DistinctPaths()))
	w("")
	w("  %sDATA FLOW%s   read %s · wrote %s · %snet out %s%s",
		ansiDim, ansiReset, bytesOf(t.FileReadBytes), bytesOf(t.FileWriteBytes),
		egressColor(t.NetWriteBytes), bytesOf(t.NetWriteBytes), ansiReset)
	w("  %sIDLE%s        %s syscalls · %d bursts · %s egress",
		ansiDim, ansiReset, num(snap.Idle.SyscallCount()), len(snap.IdleBursts), bytesOf(snap.Idle.NetWriteBytes))
	w("  %sPIPELINE%s    %s events · %s dropped",
		ansiDim, ansiReset, num64(snap.Stats.EventsIngested), num64(snap.Stats.EventsDropped))
	w("")

	w("  %sFINDINGS%s", ansiDim, ansiReset)
	if len(findings) == 0 {
		w("    %snone%s", ansiDim, ansiReset)
	}
	for i, f := range findings {
		if i >= 6 {
			w("    %s… and %d more (`findings` for all)%s", ansiDim, len(findings)-i, ansiReset)
			break
		}
		sc := severityColor(f.Severity)
		w("    %s%-9s%s %s%-26s%s %s", sc, f.Severity, ansiReset, ansiDim, f.Detector, ansiReset, trunc(f.Title, 46))
	}
	w("")
	w("  %spress Enter to return to the prompt%s", ansiDim, ansiReset)
	// Erase any taller previous frame.
	for i := 0; i < 6; i++ {
		b.WriteString(ansiClearLn + "\n")
	}
	fmt.Print(b.String())
}

func printFinalReport(score analyze.Score, snap *analyze.Snapshot, findings []analyze.Finding, narrative analyze.Narrative, auditPath string) {
	fmt.Printf("%s%s session report%s\n", ansiBold, colAccent, ansiReset)
	printPosture(score)
	fmt.Println()
	fmt.Printf("  requests     %s served, %s failed (%.2f%% errors)\n",
		num(snap.Requests), num(snap.Failures), score.Reliability.ErrorRate*100)
	fmt.Printf("  latency      p50 %s · p95 %s · p99 %s\n", msOf(snap.Latency.P50), msOf(snap.Latency.P95), msOf(snap.Latency.P99))
	fmt.Printf("  observed     %s syscalls · %s paths · %s spawns\n",
		num(snap.Totals.SyscallCount()), num(snap.Totals.DistinctPaths()), num(snap.Totals.Forks))
	fmt.Printf("  data flow    %s read · %s written · %s out to network\n",
		bytesOf(snap.Totals.FileReadBytes), bytesOf(snap.Totals.FileWriteBytes), bytesOf(snap.Totals.NetWriteBytes))
	fmt.Println()
	printNarrative(narrative)
	fmt.Println()
	printFindings(findings, 20)
	fmt.Println()
	detail("audit chain kept at %s — verify it with: warden-audit -verify %s", auditPath, auditPath)
}

// ---- small formatters ---------------------------------------------------

func num(n int) string { return addCommas(fmt.Sprint(n)) }

func num64(n int64) string { return addCommas(fmt.Sprint(n)) }

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

// wrap breaks text at width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var out strings.Builder
	lineLen := 0
	for i, word := range words {
		if lineLen > 0 && lineLen+1+len(word) > width {
			out.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			out.WriteString(" ")
			lineLen++
		}
		out.WriteString(word)
		lineLen += len(word)
	}
	return out.String()
}
