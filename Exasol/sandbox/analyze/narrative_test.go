package analyze

import (
	"strings"
	"testing"
)

func mkFinding(detector string, sev Severity, conf Confidence, title string) Finding {
	return mk(fakeDetector{name: detector}, "k", sev, conf, title, "detail")
}

type fakeDetector struct{ name string }

func (f fakeDetector) Name() string                { return f.name }
func (f fakeDetector) Family() Family              { return FamilyDataFlow }
func (f fakeDetector) Inspect(*Snapshot) []Finding { return nil }

func TestBuildNarrative_CorrelatesExfiltrationPattern(t *testing.T) {
	findings := []Finding{
		mkFinding("read-then-egress", SeverityCritical, ConfidenceDeterministic, "credential read followed by egress"),
		mkFinding("credential-access", SeverityCritical, ConfidenceDeterministic, "credential store accessed outside the profile"),
		mkFinding("egress-volume", SeverityHigh, ConfidenceStatistical, "egress exceeds response size"),
	}
	sc := Score{Posture: TierQuarantine, PostureReason: "confirmed exfiltration-shaped sequence", AnalysisHealthy: true}

	n := BuildNarrative(sc, findings)
	if n.Tier != TierQuarantine {
		t.Fatalf("want tier quarantine, got %s", n.Tier)
	}
	found := false
	for _, p := range n.Points {
		if p == correlationRules[0].explanation {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected exfiltration correlation point, got %+v", n.Points)
	}
}

func TestBuildNarrative_NoFindingsIsClean(t *testing.T) {
	sc := Score{Posture: TierTrusted, PostureReason: "no deviation observed", AnalysisHealthy: true}
	n := BuildNarrative(sc, nil)
	if n.Tier != TierTrusted {
		t.Fatalf("want trusted, got %s", n.Tier)
	}
	if n.Headline == "" {
		t.Fatalf("expected a non-empty headline")
	}
}

func TestBuildNarrative_UncorrelatedFindingStillReported(t *testing.T) {
	findings := []Finding{
		mkFinding("process-spawn", SeverityLow, ConfidenceHeuristic, "new processes created while serving"),
	}
	sc := Score{Posture: TierWatch, PostureReason: "advisory signals outside the deterministic set", AnalysisHealthy: true}
	n := BuildNarrative(sc, findings)
	joined := ""
	for _, p := range n.Points {
		joined += p + "\n"
	}
	if !strings.Contains(joined, "process-spawn") {
		t.Fatalf("expected the uncorrelated finding to still appear in points, got %+v", n.Points)
	}
}
