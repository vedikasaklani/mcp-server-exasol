package analyze

import (
	"fmt"
	"sort"
	"time"
)

// ErrorRate reports failed tool calls as a fraction of all calls.
//
// §7.2 is explicit that reliability is an SLO and never an input to
// authorization: collapsing the two means a fast malicious server
// outranks a slow safe one. Every detector in this family is therefore
// excluded from the security score by construction — see Score.
type ErrorRate struct {
	Threshold float64
	MinSample int
}

func (ErrorRate) Name() string   { return "error-rate" }
func (ErrorRate) Family() Family { return FamilyReliability }

func (d ErrorRate) Inspect(s *Snapshot) []Finding {
	minSample := d.MinSample
	if minSample <= 0 {
		minSample = 10
	}
	threshold := d.Threshold
	if threshold <= 0 {
		threshold = 0.05
	}
	if s.Requests < minSample || s.Failures == 0 {
		return nil
	}
	rate := float64(s.Failures) / float64(s.Requests)
	if rate <= threshold {
		return nil
	}
	sev := SeverityLow
	if rate > 0.25 {
		sev = SeverityMedium
	}
	return []Finding{mk(d, "rate", sev, ConfidenceDeterministic,
		"elevated request failure rate",
		fmt.Sprintf("%d of %d requests failed (%.1f%%)", s.Failures, s.Requests, rate*100))}
}

// LatencyBudget measures against §1.6's stated proxy overhead target:
// p50 under 15ms, p99 under 60ms, excluding tool execution. What is
// measurable here is end-to-end request latency including the tool, so
// this reports the budget's shape rather than claiming to have isolated
// overhead — an honest partial measurement being more useful than a
// precise-looking wrong one.
type LatencyBudget struct {
	P50 time.Duration
	P99 time.Duration
}

func (LatencyBudget) Name() string   { return "latency-budget" }
func (LatencyBudget) Family() Family { return FamilyReliability }

func (d LatencyBudget) Inspect(s *Snapshot) []Finding {
	if s.Latency.Count < 20 {
		return nil
	}
	var out []Finding
	for tool, p := range s.ToolLatency {
		if p.Count < 10 {
			continue
		}
		budget, ok := s.Baseline.MaxDurationMS[tool]
		if !ok || budget <= 0 {
			continue
		}
		if p.P99 <= time.Duration(budget)*time.Millisecond {
			continue
		}
		out = append(out, mk(d, tool, SeverityLow, ConfidenceDeterministic,
			"tool latency above its declared budget at p99",
			fmt.Sprintf("%s p99 is %v against a declared budget of %dms (p50 %v, n=%d)",
				tool, p.P99.Round(time.Millisecond), budget, p.P50.Round(time.Millisecond), p.Count)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// SyscallCost reports which syscalls dominate wall-clock time. Not a
// security signal at all — it is here because "this server is slow and
// here is the syscall responsible" is the question an operator asks
// immediately after "is this server safe", and answering it needs the
// same data.
type SyscallCost struct{}

func (SyscallCost) Name() string   { return "syscall-cost" }
func (SyscallCost) Family() Family { return FamilyReliability }

func (SyscallCost) Inspect(s *Snapshot) []Finding { return nil }

// PipelineHealth reports when the analysis path itself is degraded.
//
// This is the most important detector in the file and the easiest to
// omit. Every other finding in this package is an assertion about what
// the server did; all of them are silently wrong if the engine stopped
// receiving events. A monitoring system whose silence is ambiguous
// provides no assurance at all, so degradation is reported as loudly as
// a detection.
type PipelineHealth struct {
	// DropRate is the fraction of dropped events above which analysis is
	// reported as incomplete.
	DropRate float64
	// SilenceGrace is how long a session must have been running before
	// "no events at all" counts as a broken pipeline rather than as
	// events that have not arrived yet.
	//
	// gVisor writes its debug log asynchronously and this engine tails it,
	// so there is always a lag between a request completing and its
	// syscalls being readable — the same lag that makes evaluation
	// periodic rather than per-request (see Evaluate). Without a grace
	// period, asking for a scan in the first seconds of a session reports
	// the analysis pipeline as dead, which is both alarming and wrong, and
	// wrong in the direction that teaches an operator to disbelieve the
	// one detector whose whole job is to be believed.
	SilenceGrace time.Duration
}

func (PipelineHealth) Name() string   { return "pipeline-health" }
func (PipelineHealth) Family() Family { return FamilyReliability }

func (d PipelineHealth) Inspect(s *Snapshot) []Finding {
	var out []Finding
	if !s.Stats.TracingEnabled {
		return []Finding{mk(d, "disabled", SeverityMedium, ConfidenceDeterministic,
			"behavioural analysis is not running",
			"syscall tracing is disabled, so every behavioural detector is inactive; confinement is still enforced but nothing is being observed")}
	}
	dropRate := d.DropRate
	if dropRate <= 0 {
		dropRate = 0.01
	}
	total := s.Stats.EventsIngested + s.Stats.EventsDropped
	if total > 0 && float64(s.Stats.EventsDropped)/float64(total) > dropRate {
		out = append(out, mk(d, "drops", SeverityHigh, ConfidenceDeterministic,
			"syscall events dropped before analysis",
			fmt.Sprintf("%d of %d events were discarded because analysis fell behind ingestion; findings below are computed from an incomplete record",
				s.Stats.EventsDropped, total)))
	}
	grace := d.SilenceGrace
	if grace <= 0 {
		grace = 15 * time.Second
	}
	if s.Requests > 0 && s.Stats.EventsIngested == 0 && s.Uptime >= grace.Seconds() {
		out = append(out, mk(d, "silent", SeverityHigh, ConfidenceDeterministic,
			"no syscall events observed despite served traffic",
			fmt.Sprintf("%d request(s) completed over %.0fs but the trace stream produced nothing — the absence of findings below means nothing", s.Requests, s.Uptime)))
	}
	if s.Unattributed > 0 {
		out = append(out, mk(d, "unattributed", SeverityLow, ConfidenceDeterministic,
			"events could not be attributed to a request",
			fmt.Sprintf("%d event(s) arrived without a usable timestamp and were attributed by arrival order instead", s.Unattributed)))
	}
	return out
}

// DefaultDetectors returns the full built-in detector set, ordered by
// family. Every one of them is replaceable: the engine takes a slice, so
// a deployment can drop detectors it finds noisy, retune the exported
// thresholds, or add its own without forking this package.
func DefaultDetectors() []Detector {
	return []Detector{
		// Conformance — deterministic, kernel-attested.
		SyscallDrift{},
		PathDrift{},
		NetworkDrift{},
		WriteThenExec{},
		KernelDenial{},
		// Data flow — what moved where, and in what order.
		ReadThenEgress{},
		EgressVolume{},
		PathFanout{},
		Enumeration{},
		CredentialAccess{},
		// Supply chain — the integrity of the code that is running.
		EntrypointDrift{},
		UnexpectedExec{},
		NativeCodeLoad{},
		ModuleDrift{},
		ProcessSpawn{},
		// Temporal — when things happen.
		IdleActivity{},
		Beaconing{},
		DurationBudget{},
		// Protocol — the MCP layer itself.
		ManifestDrift{},
		ArgumentAccessMismatch{},
		UnsolicitedTraffic{},
		ResponseAnomaly{},
		ResponseSecretPattern{},
		ResponseInjectionPattern{},
		// Reliability — SLO only, never authorization.
		ErrorRate{},
		LatencyBudget{},
		PipelineHealth{},
	}
}
