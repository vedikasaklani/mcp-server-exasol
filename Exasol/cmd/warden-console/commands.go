package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mcp-warden/sandbox/audit"
	"mcp-warden/sandbox/runtime"
)

// cmdReputation shows the three pillars the trust/reputation platform
// exists to serve, read straight from Exasol via telemetry_api.py:
// discovery (declared vs. observed tools), reputation (the computed trust
// score), and the audit trail (recent kernel-observed calls). This is
// warden's own data landing somewhere durable and queryable — not a local
// summary of what's in memory.
func (c *console) cmdReputation(ctx context.Context) {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	if c.sess.serverID == "" {
		fail("this session has no server_id — storage was off or the telemetry service was unreachable at load time")
		return
	}
	sid := c.sess.serverID
	fmt.Printf("\n  %sserver_id%s %s\n\n", ansiDim, ansiReset, sid)

	fmt.Println("  DISCOVERY — declared vs. observed tools")
	tools, err := c.storage.GetTools(ctx, sid)
	if err != nil {
		fail("  %v", err)
	} else if len(tools) == 0 {
		detail("  nothing recorded yet")
	} else {
		for _, t := range tools {
			fmt.Printf("    %-24s %s%-9s%s %s\n", t.Name, ansiDim, "["+t.Source+"]", ansiReset, trunc(oneLine(t.Description), 60))
		}
	}

	fmt.Println("\n  REPUTATION — computed trust score")
	// Recompute before reading. The rollup is designed as a scheduled job,
	// but someone asking for a score right after running a server wants
	// that server's score, not yesterday's — and "not computed yet" for a
	// session that just finished is a confusing thing to be told.
	if err := c.storage.ComputeScores(ctx); err != nil {
		detail("  could not refresh scores (%v); showing the last computed value", err)
	}
	score, err := c.storage.GetTrustScore(ctx, sid)
	if err != nil {
		detail("  no score available: %v", err)
	} else {
		fmt.Printf("    overall %s%.1f%s   security %.1f   operational %.1f\n",
			colAccent, score.OverallScore, ansiReset, score.SecurityScore, score.OperationalScore)
		fmt.Printf("    %spenalties: static %.1f · runtime findings %.1f   (%.0f call(s) in window, computed %s)%s\n",
			ansiDim, score.StaticPenalty, score.RuntimeFindingPenalty,
			score.TotalCallsInWindow, score.ComputedAt, ansiReset)
	}

	fmt.Println("\n  RUNTIME FINDINGS — what the analyzer saw while it ran")
	findings, err := c.storage.GetRuntimeFindings(ctx, sid, 10)
	if err != nil {
		fail("  %v", err)
	} else if len(findings) == 0 {
		detail("  none recorded")
	} else {
		for _, f := range findings {
			attested := f.Confidence
			if f.KernelAttested {
				attested = "kernel-attested"
			}
			seen := ""
			if f.Sessions > 1 {
				seen = fmt.Sprintf(" in %.0f sessions", f.Sessions)
			}
			fmt.Printf("    %s%-9s%s %-22s %-40s %s\n",
				severityColorName(f.Severity), strings.ToLower(f.Severity), ansiReset,
				f.Detector, trunc(oneLine(f.Title), 40), ansiDim+attested+seen+ansiReset)
		}
	}

	fmt.Println("\n  AUDIT TRAIL — recent kernel-observed calls")
	events, err := c.storage.GetRuntimeEvents(ctx, sid, 10)
	if err != nil {
		fail("  %v", err)
	} else if len(events) == 0 {
		detail("  nothing recorded yet")
	} else {
		for _, e := range events {
			flag := ""
			if e.SensitiveDataFlag {
				flag = "  " + colSerious + "sensitive-data" + ansiReset
			}
			fmt.Printf("    %-20s %-9s %6.0fms  %s%s\n", e.ToolName, e.Decision, e.LatencyMS, e.DecisionReason, flag)
		}
	}

	sessions, err := c.storage.GetSessions(ctx, sid, 5)
	if err == nil && len(sessions) > 0 {
		fmt.Println("\n  SESSION HISTORY")
		for _, s := range sessions {
			fmt.Printf("    %-22s %-11s %.0f req, %.0f denial(s), %.0fC/%.0fH  %s\n",
				s.SessionID, s.Posture, s.Requests, s.Denials, s.Critical, s.High,
				ansiDim+s.Confinement+ansiReset)
		}
	}
	fmt.Println()
}

// severityColorName maps the severity string the API returns onto the same
// colours the local finding list uses, so a finding reads the same whether
// it came from memory or from Exasol.
func severityColorName(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return colCritical
	case "HIGH":
		return colSerious
	case "MEDIUM":
		return colWarning
	}
	return ansiDim
}

// toolInfo is one entry from the server's advertised manifest.
type toolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var toolsMu sync.Mutex

// rememberTools caches the manifest seen during the warmup handshake, so
// `tools` can answer without spending a container round trip — and so it
// still answers if the server later stops responding.
func (s *session) rememberTools(payload []byte) {
	var msg struct {
		Result struct {
			Tools []toolInfo `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil || len(msg.Result.Tools) == 0 {
		return
	}
	toolsMu.Lock()
	s.tools = msg.Result.Tools
	toolsMu.Unlock()
}

func (s *session) toolList() []toolInfo {
	toolsMu.Lock()
	defer toolsMu.Unlock()
	return append([]toolInfo(nil), s.tools...)
}

// send puts one JSON-RPC payload through the confined pool.
func (c *console) send(ctx context.Context, toolName string, payload []byte) ([]byte, error) {
	if c.sess == nil {
		return nil, fmt.Errorf("nothing loaded — `load <source>` first")
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.sess.reqTimeout())
	defer cancel()

	res, err := c.sess.pool.Do(reqCtx, runtime.ExecRequest{
		ToolName: toolName,
		Payload:  payload,
		Timeout:  c.sess.reqTimeout(),
	})
	if err != nil {
		return nil, err
	}
	if n := len(res.Unsolicited); n > 0 {
		detail("%d unsolicited message(s) arrived alongside this response", n)
	}
	return res.Payload, nil
}

func (s *session) reqTimeout() time.Duration { return 30 * time.Second }

func (c *console) cmdTools(ctx context.Context) {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	tools := c.sess.toolList()
	if len(tools) == 0 {
		// Nothing was captured at handshake; ask the server directly.
		resp, err := c.send(ctx, "tools/list", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err != nil {
			fail("tools/list: %v", err)
			return
		}
		c.sess.rememberTools(resp)
		tools = c.sess.toolList()
	}
	if len(tools) == 0 {
		fail("the server advertised no tools")
		return
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	fmt.Printf("\n  %d tool(s)\n", len(tools))
	for _, t := range tools {
		fmt.Printf("    %s%-28s%s %s\n", colAccent, t.Name, ansiReset, trunc(oneLine(t.Description), 76))
		if args := schemaArgs(t.InputSchema); args != "" {
			fmt.Printf("      %sargs: %s%s\n", ansiDim, args, ansiReset)
		}
	}
	fmt.Println()
	detail(`call a tool with: call <name> {"arg":"value"}`)
}

func (c *console) cmdCall(ctx context.Context, args []string, line string) {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	if len(args) == 0 {
		fail(`usage: call <tool> [json-arguments]   e.g. call echo {"message":"hi"}`)
		return
	}
	name := args[0]

	// Take the argument JSON from the raw line so object braces and
	// spaces survive: re-joining the split fields would work for most
	// input and corrupt exactly the input with strings in it.
	argJSON := "{}"
	if i := strings.Index(line, name); i >= 0 {
		if rest := strings.TrimSpace(line[i+len(name):]); rest != "" {
			argJSON = rest
		}
	}
	if !json.Valid([]byte(argJSON)) {
		fail("arguments are not valid JSON: %s", argJSON)
		return
	}

	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`,
		time.Now().UnixNano()%100000, name, argJSON)

	start := time.Now()
	resp, err := c.send(ctx, name, []byte(payload))
	elapsed := time.Since(start)
	if err != nil {
		fail("call %s: %v", name, err)
		detail("the container that served this call has been quarantined and replaced")
		return
	}
	fmt.Printf("\n%s\n", indentJSON(resp))
	detail("%v · %d bytes", elapsed.Round(time.Millisecond), len(resp))
}

func (c *console) cmdRaw(ctx context.Context, line string) {
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "raw"))
	if body == "" {
		fail(`usage: raw {"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		return
	}
	if !json.Valid([]byte(body)) {
		fail("not valid JSON")
		return
	}
	resp, err := c.send(ctx, "raw", []byte(body))
	if err != nil {
		fail("raw: %v", err)
		return
	}
	fmt.Printf("\n%s\n", indentJSON(resp))
}

func (c *console) cmdScan() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	step("running detectors over everything observed so far")
	findings := c.sess.mon.Evaluate()
	score := c.sess.mon.Score()
	narrative := c.sess.mon.Narrative()

	// gVisor writes its debug log asynchronously and this console tails
	// it, so a call's syscalls become readable seconds after the call
	// returns. Saying so matters: a scan run immediately after a tool
	// call can show a clean session for a server that is in the middle of
	// doing something, and reading that as "clean" is the single easiest
	// way to be misled by this tool.
	if snap := c.sess.mon.Aggregate(); snap.Uptime < 15 || snap.Totals.SyscallCount() == 0 {
		detail("this session is %.0fs old — syscalls from recent calls may not have arrived yet; re-run `scan` in a few seconds to be sure", snap.Uptime)
	}

	fmt.Println()
	printPosture(score)
	fmt.Println()
	printNarrative(narrative)
	fmt.Println()
	printFindings(findings, 100)
}

func (c *console) cmdFindings() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	printFindings(c.sess.mon.Findings(), 100)
}

func (c *console) cmdStatus() {
	if c.sess == nil {
		fail("nothing loaded — `load <source>` first")
		return
	}
	snap := c.sess.mon.Aggregate()
	score := c.sess.mon.Score()

	fmt.Printf("\n  %ssource%s      %s\n", ansiDim, ansiReset, c.sess.source)
	fmt.Printf("  %starget%s      %s\n", ansiDim, ansiReset, trunc(strings.Join(c.sess.command, " "), 88))
	fmt.Printf("  %ssession%s     %s · pool %d · up %s\n", ansiDim, ansiReset, c.sess.id, c.sess.poolN, dur(time.Since(c.sess.started)))
	fmt.Println()
	printPosture(score)
	fmt.Println()
	printCounters(snap, score)
	fmt.Println()
}

func (c *console) cmdContainers() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	views := c.sess.mon.Containers()
	fmt.Printf("\n  %d container(s) — attribution is exact within one, by container across them (§6.3)\n", len(views))
	for _, v := range views {
		state := colGood + "live   " + ansiReset
		if !v.Live {
			state = ansiDim + "retired" + ansiReset
		}
		fmt.Printf("    %-20s %s  %5s req  %3s den  %8s ev  %9s read  %9s net-out\n",
			trunc(v.ID, 20), state, num(v.Requests), num(v.Denials),
			num64(v.Events), bytesOf(v.FileReadBytes), bytesOf(v.NetWriteBytes))
	}
	fmt.Println()
}

func (c *console) cmdProfile() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	p := c.sess.profile
	t := p.Tools[0]
	fmt.Printf("\n  %sapproved_by%s  %s%s%s\n", ansiDim, ansiReset, colCritical, p.ApprovedBy, ansiReset)
	fmt.Printf("  %sdigest%s       %s\n", ansiDim, ansiReset, p.ImageDigest)
	fmt.Printf("  %sgenerated%s    %s\n", ansiDim, ansiReset, p.GeneratedBy)
	if p.Entrypoint != nil {
		fmt.Printf("  %sentrypoint%s   %s\n", ansiDim, ansiReset, p.Entrypoint.SHA256)
		if p.Entrypoint.InterpreterSHA256 != "" {
			fmt.Printf("  %sinterpreter%s  %s\n", ansiDim, ansiReset, p.Entrypoint.InterpreterSHA256)
		}
	}
	fmt.Printf("  %ssyscalls%s     %d allowed; everything else returns EPERM\n", ansiDim, ansiReset, len(t.Syscalls))
	fmt.Printf("  %sread paths%s   %d\n", ansiDim, ansiReset, len(t.Filesystem.Read))
	fmt.Printf("  %swrite paths%s  %d %v\n", ansiDim, ansiReset, len(t.Filesystem.Write), t.Filesystem.Write)
	fmt.Printf("  %snetwork%s      %d declared destination(s)%s\n", ansiDim, ansiReset, len(t.Network), noNetNote(len(t.Network)))
	fmt.Printf("  %sfile%s         %s\n", ansiDim, ansiReset, c.sess.profPath)
	fmt.Println()
}

func noNetNote(n int) string {
	if n == 0 {
		return " — the container has no network interfaces at all"
	}
	return ""
}

func (c *console) cmdAudit(args []string) {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	path := c.sess.auditPath
	st := c.sess.log.Stats()

	if len(args) > 0 && args[0] == "verify" {
		step("verifying the hash chain from the file alone")
		rep, err := audit.Verify(path)
		if err != nil {
			fail("verify: %v", err)
			return
		}
		status := colGood + "VALID" + ansiReset
		if !rep.Valid {
			status = colCritical + "INVALID" + ansiReset
		}
		fmt.Printf("\n  chain     %s\n", status)
		fmt.Printf("  entries   %d (%d executions, %d findings, %d checkpoints)\n",
			rep.Entries, rep.Executions, rep.Findings, rep.Checkpoints)
		fmt.Printf("  head      %s\n", rep.ChainHead)
		if rep.Gaps > 0 {
			fmt.Printf("  %sgaps      %d markers covering %d lost entries%s\n", colSerious, rep.Gaps, rep.LostEntries, ansiReset)
		}
		for _, p := range rep.Problems {
			fmt.Printf("  %s! %s%s\n", colCritical, p, ansiReset)
		}
		fmt.Println()
		return
	}

	n := 20
	if len(args) > 0 {
		if parsed, err := strconv.Atoi(args[0]); err == nil && parsed > 0 {
			n = parsed
		}
	}
	entries, err := audit.Tail(path, n)
	if err != nil {
		fail("read chain: %v", err)
		return
	}
	fmt.Printf("\n  %s · %d entries written, %d dropped\n", path, st.Written, st.Dropped)
	for _, e := range entries {
		printAuditEntry(e)
	}
	fmt.Println()
	detail("`audit verify` recomputes every hash and checks every checkpoint signature")
}

// cmdWatch redraws a compact live view until Enter is pressed. Enter
// rather than Ctrl-C so leaving the view never risks tearing down the
// containers it is watching.
func (c *console) cmdWatch(ctx context.Context, args []string) {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	interval := time.Second
	if len(args) > 0 {
		if d, err := time.ParseDuration(args[0]); err == nil && d >= 100*time.Millisecond {
			interval = d
		}
	}

	fmt.Print(ansiHide + ansiClear)
	defer fmt.Print(ansiShow)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		c.drawWatchFrame()
		select {
		case <-ctx.Done():
			fmt.Print(ansiShow)
			return
		case _, open := <-c.lines:
			fmt.Print(ansiShow)
			if !open {
				return
			}
			return
		case <-t.C:
		}
	}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

// schemaArgs renders a tool's input schema as a short argument list.
func schemaArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var schema struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil || len(schema.Properties) == 0 {
		return ""
	}
	required := map[string]bool{}
	for _, r := range schema.Required {
		required[r] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for n := range schema.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		p := n + ":" + schema.Properties[n].Type
		if !required[n] {
			p += "?"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "  ")
}

func indentJSON(raw []byte) string {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return string(raw)
	}
	pretty, err := json.MarshalIndent(out, "  ", "  ")
	if err != nil {
		return string(raw)
	}
	return "  " + string(pretty)
}
