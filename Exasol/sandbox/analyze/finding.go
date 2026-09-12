// Package analyze is the behavioral analysis engine: it consumes the live
// syscall stream from a confined, running MCP server and turns it into
// findings, scores, and audit evidence.
//
// The organising idea is that "malicious intent" is not observable and
// nothing here pretends to observe it. What is observable is *deviation*:
// from the capability profile a human approved (§3.2), from the behaviour
// recorded when that profile was generated, and from the shape of a
// well-behaved MCP server. Every detector in this package measures one
// kind of deviation and says how much it trusts its own measurement.
//
// That confidence rating is load-bearing, not decoration. Detectors with
// Deterministic confidence are backed by kernel-attested facts — the
// syscall happened, the bytes moved, the path was outside the allowlist —
// and are safe to gate on. Detectors with Statistical or Heuristic
// confidence are advisory in exactly the sense §1.1 means it: they may
// narrow trust, they may never widen it, and a compromised or
// mistuned one can at worst raise a false alarm.
package analyze

import (
	"fmt"
	"sort"
	"time"
)

// Family groups detectors by what they inspect. The dashboard renders one
// column per family so an operator can tell at a glance whether a server
// is deviating from its profile, moving data in a suspicious shape, or
// merely slow.
type Family string

const (
	// FamilyConformance covers deviation from the approved
	// CapabilityProfile. Kernel-attested and the most trustworthy signal
	// the system has.
	FamilyConformance Family = "conformance"
	// FamilyDataFlow covers what data moved where: file reads, socket
	// writes, and the ordering between them.
	FamilyDataFlow Family = "dataflow"
	// FamilySupplyChain covers the integrity of the code actually running
	// — process spawns, library loads, module sets, entrypoint digests.
	FamilySupplyChain Family = "supplychain"
	// FamilyTemporal covers when things happen: activity outside any
	// request, periodic bursts, work continuing after a response.
	FamilyTemporal Family = "temporal"
	// FamilyProtocol covers the MCP layer itself: manifest drift,
	// unsolicited traffic, argument/access agreement.
	FamilyProtocol Family = "protocol"
	// FamilyReliability covers operational health. Per §7.2 these never
	// feed the security score.
	FamilyReliability Family = "reliability"
)

// Severity ranks how much an operator should care. Closed set: detectors
// do not get to invent severities, so filtering and sorting stay reliable.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
}

// Rank returns a sortable ordering for s, highest severity largest.
func (s Severity) Rank() int { return severityRank[s] }

// Confidence states what kind of claim a finding is making. It is the
// difference between "the kernel recorded this" and "this looked unusual
// compared to a baseline", and the two must never be presented as if they
// were the same kind of statement.
type Confidence string

const (
	// ConfidenceDeterministic means the finding restates an observed
	// fact. There is no threshold and no model: the syscall was made, the
	// path was touched, the bytes moved.
	ConfidenceDeterministic Confidence = "deterministic"
	// ConfidenceStatistical means the finding compares a measurement
	// against a baseline or threshold. True, but tunable, and therefore
	// capable of being wrong at the edges.
	ConfidenceStatistical Confidence = "statistical"
	// ConfidenceHeuristic means the finding matches a pattern believed to
	// correlate with risk. Weakest class; useful for triage, never for
	// gating.
	ConfidenceHeuristic Confidence = "heuristic"
)

// Finding is one detector's verdict about one observed behaviour.
//
// Findings are deduplicated by Key over the life of a session rather than
// appended per occurrence. A server that reads an undeclared path ten
// thousand times is one finding with a count of ten thousand, not ten
// thousand findings — the latter is how a monitoring UI becomes unusable
// in the first minute of a real workload, which this project has already
// experienced once (see the 543-finding filesystem-server run that forced
// sandbox/observe's sensitive-path patterns to be rewritten).
type Finding struct {
	Key        string     `json:"key"`
	Detector   string     `json:"detector"`
	Family     Family     `json:"family"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	// Evidence holds the raw observations behind the finding — the actual
	// paths, syscalls, or addresses. Bounded (see addEvidence): evidence
	// is for a human deciding what happened, and a human cannot read ten
	// thousand paths.
	Evidence []string `json:"evidence,omitempty"`
	// RequestID attributes the finding to a single tool call when the
	// behaviour occurred inside one. Empty means the behaviour happened
	// outside any request, which is itself meaningful (see the temporal
	// family).
	RequestID string    `json:"request_id,omitempty"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

const maxEvidence = 12

func (f *Finding) addEvidence(items ...string) {
	for _, it := range items {
		if len(f.Evidence) >= maxEvidence {
			return
		}
		for _, have := range f.Evidence {
			if have == it {
				return
			}
		}
		f.Evidence = append(f.Evidence, it)
	}
}

// String renders a finding for terminal output.
func (f Finding) String() string {
	return fmt.Sprintf("[%s/%s] %s: %s (x%d, %s)", f.Severity, f.Confidence, f.Detector, f.Title, f.Count, f.Detail)
}

// SortFindings orders findings for display: most severe first, then most
// recent, then by key so equal findings never reorder between refreshes.
// A dashboard whose rows shuffle on every poll is a dashboard nobody
// reads.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if a, b := fs[i].Severity.Rank(), fs[j].Severity.Rank(); a != b {
			return a > b
		}
		if !fs[i].LastSeen.Equal(fs[j].LastSeen) {
			return fs[i].LastSeen.After(fs[j].LastSeen)
		}
		return fs[i].Key < fs[j].Key
	})
}

// Detector inspects a session snapshot and reports what it found. This is
// the extension point: the built-in detectors (see DefaultDetectors) are
// a starting set, not a fixed one, and a deployment with its own notion
// of suspicious behaviour implements this interface and runs through the
// identical pipeline, scoring, and audit path.
//
// Inspect must be pure with respect to the snapshot: it may not mutate
// it, and it must tolerate being called repeatedly on a growing session.
// Findings it returns are merged by Key, so returning the same finding on
// every pass is the normal way to express "this is still true."
type Detector interface {
	Name() string
	Family() Family
	Inspect(*Snapshot) []Finding
}
