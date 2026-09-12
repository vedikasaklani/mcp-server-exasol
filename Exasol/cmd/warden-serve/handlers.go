package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"mcp-warden/sandbox/analyze"
	"mcp-warden/sandbox/audit"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// handleFindings returns the behavioural findings for the live session,
// most severe first.
func (s *server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings := s.mon.Evaluate()
	if fam := r.URL.Query().Get("family"); fam != "" {
		var filtered []analyze.Finding
		for _, f := range findings {
			if string(f.Family) == fam {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	writeJSON(w, map[string]any{
		"session":  s.session,
		"target":   s.target,
		"count":    len(findings),
		"findings": findings,
	})
}

// handleScore returns the two scores §7.2 requires be kept apart.
func (s *server) handleScore(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.Score())
}

// handleNarrative returns a correlated, human-readable summary of the
// session's findings — the same data /findings and /score expose, read
// across families instead of as a flat list. See analyze.BuildNarrative.
func (s *server) handleNarrative(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.Narrative())
}

// handleBehavior returns the full analysis snapshot: what the kernel
// observed, aggregated, plus the per-request windows.
func (s *server) handleBehavior(w http.ResponseWriter, r *http.Request) {
	snap := s.mon.Aggregate()
	filterDropped, tracingDropped := s.rt.TraceDegraded()
	writeJSON(w, map[string]any{
		"session":               s.session,
		"tracing":               s.tracing && !tracingDropped,
		"trace_filter_dropped":  filterDropped,
		"trace_disabled_by_rts": tracingDropped,
		"uptime_seconds":        snap.Uptime,
		"requests":              snap.Requests,
		"failures":              snap.Failures,
		"denials":               snap.Denials,
		"pipeline":              snap.Stats,
		"entrypoint":            snap.Entrypoint,
		"manifest_hash":         snap.ManifestHash,
		"totals": map[string]any{
			"syscalls":         snap.Totals.SyscallCount(),
			"errors":           snap.Totals.ErrorCount(),
			"distinct_paths":   snap.Totals.DistinctPaths(),
			"file_read_bytes":  snap.Totals.FileReadBytes,
			"file_write_bytes": snap.Totals.FileWriteBytes,
			"net_read_bytes":   snap.Totals.NetReadBytes,
			"net_write_bytes":  snap.Totals.NetWriteBytes,
			"process_spawns":   snap.Totals.Forks,
			"dials":            snap.Totals.Dials,
			"top_syscalls":     topSyscalls(snap.Totals.Syscalls, 15),
			"top_errnos":       topSyscalls(snap.Totals.Errnos, 10),
		},
		"idle": map[string]any{
			"syscalls":        snap.Idle.SyscallCount(),
			"distinct_paths":  snap.Idle.DistinctPaths(),
			"net_write_bytes": snap.Idle.NetWriteBytes,
			"bursts":          len(snap.IdleBursts),
		},
		"latency":      snap.Latency,
		"tool_latency": snap.ToolLatency,
		"recent":       snap.Recent,
	})
}

// handleContainers returns the per-container drill-down. Attribution is
// exact within a container and by container across them (§6.3), so the
// per-container view is the finest granularity that is actually true.
func (s *server) handleContainers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mon.Containers())
}

// handleAudit returns the tail of the chain and its verification status.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		http.Error(w, "audit log is not enabled (start with -audit <path>)", http.StatusNotFound)
		return
	}
	st := s.audit.Stats()
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			n = parsed
		}
	}
	entries, err := audit.Tail(st.Path, n)
	if err != nil {
		http.Error(w, "read chain: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := map[string]any{"stats": st, "entries": entries}
	if r.URL.Query().Get("verify") == "1" {
		// Verification reads the whole chain, so it is opt-in rather than
		// something a dashboard poll triggers every second.
		rep, verr := audit.Verify(st.Path)
		if verr != nil {
			out["verify_error"] = verr.Error()
		} else {
			out["verify"] = rep
		}
	}
	writeJSON(w, out)
}

// exportMetrics mirrors the analysis state into the Prometheus registry,
// so a scrape sees behavioural signal and not only request plumbing.
func (s *server) exportMetrics(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.publishMetrics()
		}
	}
}

func (s *server) publishMetrics() {
	snap := s.mon.Aggregate()
	sc := s.mon.Score()

	s.reg.Gauge("warden_syscalls_observed").Set(int64(snap.Totals.SyscallCount()))
	s.reg.Gauge("warden_distinct_paths").Set(int64(snap.Totals.DistinctPaths()))
	s.reg.Gauge("warden_file_read_bytes").Set(snap.Totals.FileReadBytes)
	s.reg.Gauge("warden_file_write_bytes").Set(snap.Totals.FileWriteBytes)
	s.reg.Gauge("warden_net_write_bytes").Set(snap.Totals.NetWriteBytes)
	s.reg.Gauge("warden_net_read_bytes").Set(snap.Totals.NetReadBytes)
	s.reg.Gauge("warden_network_destinations").Set(int64(len(snap.Totals.Dials)))
	s.reg.Gauge("warden_process_spawns").Set(int64(snap.Totals.Forks))
	s.reg.Gauge("warden_idle_syscalls").Set(int64(snap.Idle.SyscallCount()))
	s.reg.Gauge("warden_idle_net_write_bytes").Set(snap.Idle.NetWriteBytes)

	s.reg.Gauge("warden_trace_events_ingested").Set(snap.Stats.EventsIngested)
	s.reg.Gauge("warden_trace_events_dropped").Set(snap.Stats.EventsDropped)
	s.reg.Gauge("warden_trace_log_truncations").Set(snap.Stats.LogTruncations)

	s.reg.Gauge("warden_findings_critical").Set(int64(sc.Critical))
	s.reg.Gauge("warden_findings_high").Set(int64(sc.High))
	s.reg.Gauge("warden_findings_medium").Set(int64(sc.Medium))
	s.reg.Gauge("warden_findings_low").Set(int64(sc.Low))
	s.reg.Gauge("warden_findings_deterministic").Set(int64(sc.Deterministic))
	s.reg.Gauge("warden_posture_tier").Set(tierValue(sc.Posture))
	s.reg.Gauge("warden_analysis_healthy").Set(boolValue(sc.AnalysisHealthy))

	if s.audit != nil {
		st := s.audit.Stats()
		s.reg.Gauge("warden_audit_entries").Set(st.Written)
		s.reg.Gauge("warden_audit_dropped").Set(st.Dropped)
		s.reg.Gauge("warden_audit_backlog").Set(st.Backlog)
	}
}

// tierValue orders the posture tiers so an alerting rule can threshold on
// them. Higher is worse, which is the direction alerts are written in.
func tierValue(t analyze.Tier) int64 {
	switch t {
	case analyze.TierTrusted:
		return 0
	case analyze.TierWatch:
		return 1
	case analyze.TierDegraded:
		return 2
	case analyze.TierQuarantine:
		return 3
	}
	return -1
}

func boolValue(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

type kv struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func topSyscalls(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Count > out[i].Count || (out[j].Count == out[i].Count && out[j].Name < out[i].Name) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if n < len(out) {
		out = out[:n]
	}
	return out
}
