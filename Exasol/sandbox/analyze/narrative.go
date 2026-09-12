package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// Narrative is a single, human-readable summary of a session's findings,
// built by correlating across detector families rather than by listing
// them flat.
//
// A flat finding list is complete but illegible: it makes an operator do
// the correlation by hand, every time, under time pressure. The
// correlations below are pattern names for combinations of findings that
// independently point at the same underlying behaviour from different
// angles — a credential read plus an egress-volume spike plus
// read-then-egress is one event, not three, and a narrative that says so
// is worth more than the three lines that produced it.
//
// Narrative never changes the posture tier. It reads the same Score and
// Finding set every other consumer reads and adds nothing Detector.
// Inspect did not already assert — see BuildNarrative.
type Narrative struct {
	// Headline is a one-line summary: the tier, why, and the single
	// finding that best explains it.
	Headline string `json:"headline"`
	Tier     Tier   `json:"tier"`
	// Points are ordered, most-important first: the tier explanation,
	// then cross-family correlations, then a residual summary of
	// anything left over.
	Points []string `json:"points"`
}

// correlationRule names a pattern across two or more detector keys and
// the sentence to use when all of them fired.
type correlationRule struct {
	name        string
	detectors   []string
	explanation string
}

var correlationRules = []correlationRule{
	{
		name:      "exfiltration",
		detectors: []string{"read-then-egress", "credential-access", "egress-volume"},
		explanation: "credential access, an egress volume spike, and a read-then-egress ordering all fired together — " +
			"three independent measurements of the same event: this session read something sensitive and sent it out over the network.",
	},
	{
		name:      "beaconing-c2",
		detectors: []string{"beaconing", "idle-activity"},
		explanation: "idle activity is both elevated and periodic — regular-interval network contact with nobody calling the server " +
			"is the shape of command-and-control polling, not background housekeeping.",
	},
	{
		name:      "supply-chain-compromise",
		detectors: []string{"module-drift", "native-code-load"},
		explanation: "the dependency tree changed since the profile was approved AND native code loaded from a path the profile never declared — " +
			"consistent with a compromised package shipping a native payload after review.",
	},
	{
		name:      "supply-chain-compromise-exec",
		detectors: []string{"module-drift", "unexpected-exec"},
		explanation: "the dependency tree changed since approval AND the server spawned a process beyond its entrypoint — " +
			"an updated dependency now running code the reviewed version never executed.",
	},
	{
		name:      "confinement-gap",
		detectors: []string{"syscall-drift", "path-drift"},
		explanation: "syscalls AND filesystem paths both drifted outside the approved profile at once — " +
			"this is broader than one missed grant; the enforced policy and the reviewed profile have diverged.",
	},
	{
		name:      "reconnaissance",
		detectors: []string{"path-fanout", "argument-access-mismatch"},
		explanation: "one request touched an unusual number of paths, none related to what it was asked for — " +
			"the shape of inventorying the filesystem rather than serving the call.",
	},
	{
		name:      "response-content-risk",
		detectors: []string{"response-secret-pattern", "response-injection-pattern"},
		explanation: "responses matched both secret-shaped and instruction-shaped patterns — " +
			"content returned to the client carries both a plausible exfiltration payload and injected phrasing in the same session.",
	},
	{
		name:      "credential-then-instruction",
		detectors: []string{"credential-access", "response-injection-pattern"},
		explanation: "a credential store was accessed and a later response reads as an instruction rather than data — " +
			"worth checking whether the credential's contents are what is being relayed back toward the model.",
	},
}

// BuildNarrative correlates findings and summarises the session.
//
// findings need not be pre-sorted: BuildNarrative sorts its own copy
// (SortFindings order — most severe first) rather than trust the
// caller's ordering, since the headline depends on it.
func BuildNarrative(sc Score, findings []Finding) Narrative {
	findings = append([]Finding(nil), findings...)
	SortFindings(findings)

	n := Narrative{Tier: sc.Posture}

	byDetector := map[string]Finding{}
	for _, f := range findings {
		if existing, ok := byDetector[f.Detector]; !ok || f.Severity.Rank() > existing.Severity.Rank() {
			byDetector[f.Detector] = f
		}
	}

	n.Headline = narrativeHeadline(sc, findings)
	n.Points = append(n.Points, sc.PostureReason)

	var correlated map[string]bool = map[string]bool{}
	for _, rule := range correlationRules {
		if !allPresent(byDetector, rule.detectors) {
			continue
		}
		n.Points = append(n.Points, rule.explanation)
		for _, d := range rule.detectors {
			correlated[d] = true
		}
	}

	// Anything that fired but wasn't part of a named correlation still
	// deserves a line, so the narrative is a summary of everything, not
	// just of the patterns this package happened to name in advance.
	var residual []string
	for det, f := range byDetector {
		if correlated[det] || f.Severity == SeverityInfo {
			continue
		}
		residual = append(residual, fmt.Sprintf("%s (%s/%s): %s", det, f.Severity, f.Confidence, f.Title))
	}
	sort.Strings(residual)
	n.Points = append(n.Points, residual...)

	if !sc.AnalysisHealthy {
		n.Points = append(n.Points, "behavioural analysis is degraded — treat the absence of any finding above as unproven, not as clean")
	}

	return n
}

func allPresent(have map[string]Finding, want []string) bool {
	for _, d := range want {
		if _, ok := have[d]; !ok {
			return false
		}
	}
	return true
}

func narrativeHeadline(sc Score, findings []Finding) string {
	if len(findings) == 0 {
		return "no deviation observed; posture TRUSTED"
	}
	top := findings[0] // findings are pre-sorted most-severe-first by SortFindings
	return fmt.Sprintf("posture %s — %s (%s/%s)", strings.ToUpper(string(sc.Posture)), top.Title, top.Severity, top.Confidence)
}
