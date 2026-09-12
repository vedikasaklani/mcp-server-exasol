// Package registry is a best-effort client for the Postgres-free telemetry
// API in mcp-server-exasol (server_management/api/telemetry_api.py). It is
// how warden feeds the three pillars of the trust/reputation platform —
// tool discovery, reputation scoring, and the runtime audit trail — without
// making any of that a dependency of the sandbox itself.
//
// Every write here follows the same fail mode as sandbox/audit: never
// block, never fail the caller. A server being loaded and confined
// correctly must not depend on whether a separate analytics service happens
// to be reachable right now — see CONTEXT.md's own framing of Exasol as
// "intentionally best-effort" for the same reason.
package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to telemetry_api.py. A nil *Client is valid and every method
// on it is a no-op — this is what makes the storage integration optional
// throughout the rest of warden rather than something every caller has to
// nil-check separately.
type Client struct {
	baseURL string
	http    *http.Client
	// unreachable latches true after the first failed call, so a service
	// that never starts doesn't cost every subsequent request a timeout.
	// Resolve clears it on success, so a service that comes up later is
	// picked back up on the next load.
	unreachable bool
	onEvent     func(err error) // for `status`/logging; nil is fine
}

// New returns a Client pointed at baseURL (e.g. "http://localhost:8000").
// Pass "" to get a Client whose calls are all no-ops.
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 4 * time.Second},
	}
}

// Enabled reports whether this client will attempt any network call at
// all. It does not guarantee the service is reachable — see LastError.
func (c *Client) Enabled() bool { return c != nil && c.baseURL != "" }

// OnEvent registers a callback invoked with the error (nil on success)
// after every attempted call, so the console can show connectivity status.
func (c *Client) OnEvent(f func(err error)) {
	if c != nil {
		c.onEvent = f
	}
}

func (c *Client) report(err error) {
	if c == nil {
		return
	}
	c.unreachable = err != nil
	if c.onEvent != nil {
		c.onEvent(err)
	}
}

// Unreachable reports whether the most recent call failed.
func (c *Client) Unreachable() bool { return c == nil || c.unreachable }

func (c *Client) get(ctx context.Context, path string, out any) error {
	if !c.Enabled() {
		return fmt.Errorf("registry: storage disabled")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("registry: build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.report(err)
		return fmt.Errorf("registry: %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("registry: %s: HTTP %d: %s", path, resp.StatusCode, string(data))
		c.report(err)
		return err
	}
	c.report(nil)
	return json.Unmarshal(data, out)
}

// TrustScore is one day's row from FACT_TRUST_SCORE — the reputation
// pillar's read shape.
type TrustScore struct {
	ServerID              string  `json:"server_id"`
	DateKey               int     `json:"date_key"`
	SecurityScore         float64 `json:"security_score"`
	OperationalScore      float64 `json:"operational_score"`
	OverallScore          float64 `json:"overall_score"`
	StaticPenalty         float64 `json:"static_penalty"`
	RuntimeFindingPenalty float64 `json:"runtime_finding_penalty"`
	RuntimeViolationCount float64 `json:"runtime_violation_count"`
	RuntimeExfilFlagCount float64 `json:"runtime_exfil_flag_count"`
	SuccessRate           float64 `json:"success_rate"`
	P95LatencyMS          float64 `json:"p95_latency_ms"`
	TotalCallsInWindow    float64 `json:"total_calls_in_window"`
	ComputedAt            string  `json:"computed_at"`
}

// ComputeScores asks the service to run the trust-score rollup now.
// Synchronous: the caller is about to display the result, and a score
// computed after it is printed is no use. Best-effort like everything
// else here — a failure just means the displayed score is the last one
// computed rather than a fresh one.
func (c *Client) ComputeScores(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}
	return c.post(ctx, "/compute-scores", map[string]any{}, nil)
}

// GetTrustScore fetches the reputation pillar's latest row for serverID.
// Returns nil, nil if none has been computed yet (trust_score.sql hasn't
// run since this server started producing data).
func (c *Client) GetTrustScore(ctx context.Context, serverID string) (*TrustScore, error) {
	var ts TrustScore
	if err := c.get(ctx, "/servers/"+serverID+"/trust-score", &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

// RuntimeEventRow is one row as the audit-trail read endpoint returns it.
type RuntimeEventRow struct {
	EventID                 string   `json:"event_id"`
	ToolName                string   `json:"tool_name"`
	EventTS                 string   `json:"event_ts"`
	Decision                string   `json:"decision"`
	DecisionReason          string   `json:"decision_reason"`
	SensitiveDataFlag       bool     `json:"sensitive_data_flag"`
	SensitiveDataCategories []string `json:"sensitive_data_categories"`
	DestinationMatch        *bool    `json:"destination_match"`
	LatencyMS               float64  `json:"latency_ms"`
	BytesSent               float64  `json:"bytes_sent"`
	BytesReceived           float64  `json:"bytes_received"`
	SessionID               string   `json:"session_id"`
}

// GetRuntimeEvents fetches the audit-trail pillar: the most recent
// kernel-observed tool calls for serverID, newest first.
func (c *Client) GetRuntimeEvents(ctx context.Context, serverID string, limit int) ([]RuntimeEventRow, error) {
	var rows []RuntimeEventRow
	if err := c.get(ctx, fmt.Sprintf("/servers/%s/runtime-events?limit=%d", serverID, limit), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// RuntimeFindingRow is one row as the findings read endpoint returns it.
type RuntimeFindingRow struct {
	EventTS        string  `json:"event_ts"`
	Detector       string  `json:"detector"`
	Family         string  `json:"family"`
	Severity       string  `json:"severity"`
	Confidence     string  `json:"confidence"`
	KernelAttested bool    `json:"kernel_attested"`
	Title          string  `json:"title"`
	Detail         string  `json:"detail"`
	Occurrences    float64 `json:"occurrences"`
	// Sessions is how many distinct runs saw this same condition — a
	// fault in three consecutive sessions is a different claim from one
	// seen once.
	Sessions float64 `json:"sessions"`
}

// GetRuntimeFindings fetches behavioural findings for serverID, most
// severe first.
func (c *Client) GetRuntimeFindings(ctx context.Context, serverID string, limit int) ([]RuntimeFindingRow, error) {
	var rows []RuntimeFindingRow
	if err := c.get(ctx, fmt.Sprintf("/servers/%s/runtime-findings?limit=%d", serverID, limit), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// SessionRow is one row as the sessions read endpoint returns it.
type SessionRow struct {
	SessionID     string  `json:"session_id"`
	StartedAt     string  `json:"started_at"`
	Posture       string  `json:"posture"`
	PostureReason string  `json:"posture_reason"`
	Critical      float64 `json:"critical"`
	High          float64 `json:"high"`
	Requests      float64 `json:"requests"`
	Denials       float64 `json:"denials"`
	Confinement   string  `json:"confinement"`
}

// GetSessions fetches past sessions for serverID, newest first.
func (c *Client) GetSessions(ctx context.Context, serverID string, limit int) ([]SessionRow, error) {
	var rows []SessionRow
	if err := c.get(ctx, fmt.Sprintf("/servers/%s/sessions?limit=%d", serverID, limit), &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// DiscoveredTool is one row from the discovery pillar's DIM_TOOL catalog.
type DiscoveredTool struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	ParameterSchema any    `json:"parameter_schema"`
	Source          string `json:"source"`
	UpdatedAt       string `json:"updated_at"`
}

// GetTools fetches the discovery pillar's catalog for serverID.
func (c *Client) GetTools(ctx context.Context, serverID string) ([]DiscoveredTool, error) {
	var rows []DiscoveredTool
	if err := c.get(ctx, "/servers/"+serverID+"/tools", &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	if !c.Enabled() {
		return nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("registry: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("registry: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		c.report(err)
		return fmt.Errorf("registry: %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("registry: %s: HTTP %d: %s", path, resp.StatusCode, string(data))
		c.report(err)
		return err
	}
	c.report(nil)
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// postAsync fires the request from a new goroutine and drops the result —
// used for every write except Resolve, which the caller needs the id back
// from before it can tag anything else.
func (c *Client) postAsync(path string, body any) {
	if !c.Enabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.post(ctx, path, body, nil)
	}()
}

// Resolve gets or creates a server_id for source (a git URL, "npm:<pkg>",
// or a path/cmd string) — synchronous and short-timeout, since everything
// else this session sends needs the id it returns. Returns "" (not an
// error) if the service is unreachable, in which case the caller should
// treat this session as having storage disabled rather than fail the load.
func (c *Client) Resolve(ctx context.Context, source, kind, ref string) string {
	if !c.Enabled() {
		return ""
	}
	var out struct {
		ServerID string `json:"server_id"`
	}
	if err := c.post(ctx, "/servers/resolve", map[string]string{
		"source": source, "kind": kind, "ref": ref,
	}, &out); err != nil {
		return ""
	}
	return out.ServerID
}

// ToolInfo is the discovery-catalog shape both /tools and /sast-findings
// accept — description and args, not just a name.
type ToolInfo struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	ParameterSchema any    `json:"parameter_schema,omitempty"`
}

// PostToolDiscovery records tools with a given discovery source
// ("declared" from SAST's static extraction, "observed" from warden's live
// tools/list capture). Fire-and-forget.
func (c *Client) PostToolDiscovery(serverID string, tools []ToolInfo, source string) {
	if serverID == "" {
		return
	}
	c.postAsync(fmt.Sprintf("/servers/%s/tools", serverID), map[string]any{
		"tools": tools, "source": source,
	})
}

// Finding is one SAST finding, shaped like static_analysis.py's own output.
type Finding struct {
	Analyzer string `json:"analyzer,omitempty"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message,omitempty"`
}

// PostSASTFindings records one scan's findings and declared tools, and
// marks the server scanned at ref (for rescan-on-change comparison).
// Fire-and-forget.
func (c *Client) PostSASTFindings(serverID string, findings []Finding, tools []ToolInfo, ref string) {
	if serverID == "" {
		return
	}
	c.postAsync(fmt.Sprintf("/servers/%s/sast-findings", serverID), map[string]any{
		"findings": findings, "tool_declarations": tools, "ref": ref,
	})
}

// RuntimeEvent is one tool call's audit record, field-mapped onto
// FACT_RUNTIME_EVENTS — see docs/EXASOL_INTEGRATION.md for the exact
// mapping from warden's own audit.Entry/analyze types onto these fields.
type RuntimeEvent struct {
	EventID                 string   `json:"event_id"`
	ToolName                string   `json:"tool_name"`
	SessionID               string   `json:"session_id"`
	EventTS                 string   `json:"event_ts,omitempty"` // RFC3339; empty means "now" server-side
	DestinationDeclared     string   `json:"destination_declared,omitempty"`
	DestinationActual       string   `json:"destination_actual,omitempty"`
	DestinationMatch        *bool    `json:"destination_match,omitempty"`
	SensitiveDataFlag       bool     `json:"sensitive_data_flag"`
	SensitiveDataCategories []string `json:"sensitive_data_categories,omitempty"`
	Decision                string   `json:"decision"` // ALLOWED | BLOCKED | FLAGGED
	DecisionReason          string   `json:"decision_reason,omitempty"`
	LatencyMS               int64    `json:"latency_ms"`
	StatusCode              int      `json:"status_code"`
	BytesSent               int      `json:"bytes_sent"`
	BytesReceived           int      `json:"bytes_received"`
	RetryCount              int      `json:"retry_count"`

	// §8.1's identity and sandbox fields. LearningMode is required rather
	// than optional for the reason CLAUDE.md gives: an unconfined
	// execution must never be readable as a confined one.
	RequestID      string `json:"request_id,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	RPCPayloadHash string `json:"rpc_payload_hash,omitempty"`
	LearningMode   bool   `json:"learning_mode"`
	Posture        string `json:"posture,omitempty"`
	// Sandbox counters, omitted when zero — and zero here almost always
	// means "not observed yet" rather than "did nothing". gVisor writes
	// its trace asynchronously, so a call's syscalls routinely have not
	// been parsed by the time the call itself returns. Omitting the field
	// stores NULL, which says "unknown"; sending 0 would assert the call
	// touched nothing, which is a different and false claim. The session
	// summary, written at teardown after the lag has passed, carries the
	// accurate totals.
	SyscallCount   int   `json:"syscall_count,omitempty"`
	DistinctPaths  int   `json:"distinct_paths,omitempty"`
	FileReadBytes  int64 `json:"file_read_bytes,omitempty"`
	FileWriteBytes int64 `json:"file_write_bytes,omitempty"`
	ProcessSpawns  int   `json:"process_spawns,omitempty"`
	SeccompDenials int   `json:"seccomp_denials,omitempty"`
	UnsolicitedMsg int   `json:"unsolicited_msgs,omitempty"`
}

// RuntimeFinding is one behavioural detection, for FACT_RUNTIME_FINDINGS.
// KernelAttested is the deterministic/statistical split §7.2 insists on
// keeping visible — the trust score weights the two differently.
type RuntimeFinding struct {
	SessionID      string   `json:"session_id,omitempty"`
	RequestID      string   `json:"request_id,omitempty"`
	ToolName       string   `json:"tool_name,omitempty"`
	Detector       string   `json:"detector"`
	Family         string   `json:"family,omitempty"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence,omitempty"`
	KernelAttested bool     `json:"kernel_attested"`
	Title          string   `json:"title,omitempty"`
	Detail         string   `json:"detail,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	Occurrences    int      `json:"occurrences,omitempty"`
}

// PostRuntimeFinding records one behavioural finding. Fire-and-forget.
func (c *Client) PostRuntimeFinding(serverID string, f RuntimeFinding) {
	if serverID == "" {
		return
	}
	c.postAsync(fmt.Sprintf("/servers/%s/runtime-findings", serverID), map[string]any{
		"findings": []RuntimeFinding{f},
	})
}

// SessionSummary is one confined session's closing record, for
// FACT_SESSION — the row a dashboard reads before drilling into calls.
type SessionSummary struct {
	SessionID          string  `json:"session_id"`
	StartedAt          string  `json:"started_at,omitempty"`
	EndedAt            string  `json:"ended_at,omitempty"`
	DurationSeconds    float64 `json:"duration_seconds"`
	Posture            string  `json:"posture"`
	PostureReason      string  `json:"posture_reason,omitempty"`
	Critical           int     `json:"critical"`
	High               int     `json:"high"`
	Medium             int     `json:"medium"`
	Low                int     `json:"low"`
	KernelAttested     int     `json:"kernel_attested"`
	Requests           int     `json:"requests"`
	Failures           int     `json:"failures"`
	Denials            int     `json:"denials"`
	P50LatencyMS       int64   `json:"p50_latency_ms"`
	P95LatencyMS       int64   `json:"p95_latency_ms"`
	P99LatencyMS       int64   `json:"p99_latency_ms"`
	SyscallCount       int     `json:"syscall_count"`
	DistinctPaths      int     `json:"distinct_paths"`
	FileReadBytes      int64   `json:"file_read_bytes"`
	FileWriteBytes     int64   `json:"file_write_bytes"`
	NetWriteBytes      int64   `json:"net_write_bytes"`
	ProcessSpawns      int     `json:"process_spawns"`
	AnalysisHealthy    bool    `json:"analysis_healthy"`
	LearningMode       bool    `json:"learning_mode"`
	Confinement        string  `json:"confinement"`
	Runtime            string  `json:"runtime"`
	AuditEntries       int64   `json:"audit_entries"`
	AuditChainVerified bool    `json:"audit_chain_verified"`
}

// PostSession records a finished session. Synchronous, because it is sent
// as the console is tearing down and a fire-and-forget goroutine would
// race process exit — the one write here that has no second chance.
func (c *Client) PostSession(ctx context.Context, serverID string, s SessionSummary) error {
	if serverID == "" || !c.Enabled() {
		return nil
	}
	return c.post(ctx, fmt.Sprintf("/servers/%s/sessions", serverID),
		map[string]any{"session": s}, nil)
}

// PostRuntimeEvent records one tool call. Fire-and-forget — the audit
// path's own "never blocks the response path" rule applies here too.
func (c *Client) PostRuntimeEvent(serverID string, ev RuntimeEvent) {
	if serverID == "" {
		return
	}
	c.postAsync(fmt.Sprintf("/servers/%s/runtime-events", serverID), map[string]any{
		"events": []RuntimeEvent{ev},
	})
}
