package analyze

import "time"

// Tier is a discrete security posture, per §7.2. Tiers rather than a
// continuous score because "why did this drop from 71 to 68" has no
// useful answer, and because a number invites averaging — which is how a
// critical confinement gap gets diluted by a hundred clean requests.
type Tier string

const (
	// TierTrusted means no deterministic deviation has been observed and
	// the analysis pipeline is healthy.
	TierTrusted Tier = "trusted"
	// TierWatch means only advisory signals fired: statistical outliers
	// or heuristic pattern matches, nothing kernel-attested.
	TierWatch Tier = "watch"
	// TierDegraded means confirmed deviation from the approved profile,
	// or that analysis cannot currently see what the server is doing.
	TierDegraded Tier = "degraded"
	// TierQuarantine means a confinement gap or an exfiltration-shaped
	// sequence was observed. §9's sandbox row: closed, quarantine
	// instance.
	TierQuarantine Tier = "quarantine"
)

// Score is the pair of scores §7.2 requires be kept separate. They are
// separate fields of one struct rather than one number with two
// contributors, because the entire point is that neither may be traded
// against the other.
type Score struct {
	// Posture gates admission. Derived only from security families.
	Posture Tier `json:"posture"`
	// PostureReason names what drove the tier, so an operator does not
	// have to reverse-engineer it from the finding list.
	PostureReason string `json:"posture_reason"`
	// Reliability is an SLO measurement and is never an input to
	// authorization.
	Reliability Reliability `json:"reliability"`
	// Counts by severity across security families only.
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	// Deterministic is how many of the findings are kernel-attested
	// facts rather than statistical judgements. An operator triaging a
	// long list should start here.
	Deterministic int `json:"deterministic_findings"`
	// AnalysisHealthy is false when the pipeline is degraded, in which
	// case a clean posture means "nothing was seen", not "nothing
	// happened".
	AnalysisHealthy bool `json:"analysis_healthy"`
}

// Reliability is the operational SLO half.
type Reliability struct {
	Requests     int           `json:"requests"`
	Failures     int           `json:"failures"`
	ErrorRate    float64       `json:"error_rate"`
	P50          time.Duration `json:"p50_ns"`
	P99          time.Duration `json:"p99_ns"`
	UptimeSecond float64       `json:"uptime_seconds"`
}

// securityFamilies are the families that feed the posture tier.
// Reliability is deliberately absent.
var securityFamilies = map[Family]bool{
	FamilyConformance: true,
	FamilyDataFlow:    true,
	FamilySupplyChain: true,
	FamilyTemporal:    true,
	FamilyProtocol:    true,
}

// Score computes both scores from the current findings.
//
// The tier rules are intentionally blunt. A single deterministic critical
// finding quarantines, whatever else is true, because the alternative —
// weighing it against clean traffic — is the exact mistake §7.2 names. A
// statistical critical cannot quarantine on its own, because §1.1 says a
// component fed attacker-influenceable input may narrow trust but never
// widen it, and a detector an attacker can trigger at will must not be
// able to take a server down either.
func (e *Engine) Score() Score {
	// Evaluate rather than read the stored set. A Score that reports
	// "trusted" because no one happened to run the detectors first is
	// indistinguishable from a Score that reports "trusted" because the
	// server is clean, and the two must never be confusable. Detectors
	// are pure functions over a snapshot, so running them here is cheap
	// and idempotent.
	findings := e.Evaluate()
	snap := e.Snapshot()

	sc := Score{Posture: TierTrusted, PostureReason: "no deviation observed", AnalysisHealthy: true}

	var detCritical, detHigh, statCritical, anyMedium bool
	for _, f := range findings {
		if f.Family == FamilyReliability {
			if f.Detector == (PipelineHealth{}).Name() && f.Severity.Rank() >= SeverityMedium.Rank() {
				sc.AnalysisHealthy = false
			}
			continue
		}
		if !securityFamilies[f.Family] {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			sc.Critical++
		case SeverityHigh:
			sc.High++
		case SeverityMedium:
			sc.Medium++
		case SeverityLow:
			sc.Low++
		default:
			sc.Info++
		}
		if f.Confidence == ConfidenceDeterministic {
			sc.Deterministic++
		}
		switch {
		case f.Severity == SeverityCritical && f.Confidence == ConfidenceDeterministic:
			detCritical = true
		case f.Severity == SeverityCritical:
			statCritical = true
		case f.Severity == SeverityHigh && f.Confidence == ConfidenceDeterministic:
			detHigh = true
		case f.Severity == SeverityMedium:
			anyMedium = true
		}
	}

	switch {
	case detCritical:
		sc.Posture = TierQuarantine
		sc.PostureReason = "confirmed confinement gap or exfiltration-shaped sequence"
	case detHigh:
		sc.Posture = TierDegraded
		sc.PostureReason = "confirmed deviation from the approved capability profile"
	case !sc.AnalysisHealthy:
		sc.Posture = TierDegraded
		sc.PostureReason = "behavioural analysis is degraded; absence of findings is not evidence of safety"
	case statCritical:
		sc.Posture = TierWatch
		sc.PostureReason = "advisory detector raised a critical signal; not kernel-attested"
	case sc.High > 0 || anyMedium:
		sc.Posture = TierWatch
		sc.PostureReason = "advisory signals outside the deterministic set"
	}

	sc.Reliability = Reliability{
		Requests:     snap.Requests,
		Failures:     snap.Failures,
		P50:          snap.Latency.P50,
		P99:          snap.Latency.P99,
		UptimeSecond: snap.Uptime,
	}
	if snap.Requests > 0 {
		sc.Reliability.ErrorRate = float64(snap.Failures) / float64(snap.Requests)
	}
	return sc
}
