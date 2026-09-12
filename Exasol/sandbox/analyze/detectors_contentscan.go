package analyze

import (
	"fmt"
	"sort"
)

// ResponseSecretPattern reports credential-shaped strings observed in a
// tool response payload.
//
// This is the heuristic-tier stand-in for §4.4's egress DLP, which
// belongs to the proxy gateway's response guard and is v1 — this build
// has no response guard. Pattern matching against response content can
// only narrow trust (§1.1: a component fed attacker-influenceable text
// may never widen a decision, and must not be able to take a server down
// on its own either), so this is Heuristic confidence throughout: per
// Score's tier rules, a Heuristic finding can push a session to
// TierWatch at most, never TierDegraded or TierQuarantine. Evidence
// records pattern names and window labels only, never the matched text —
// a detector whose own evidence repeats the secret it found would defeat
// the reason it exists.
type ResponseSecretPattern struct{}

func (ResponseSecretPattern) Name() string   { return "response-secret-pattern" }
func (ResponseSecretPattern) Family() Family { return FamilyProtocol }

func (d ResponseSecretPattern) Inspect(s *Snapshot) []Finding {
	patterns, windows := collectHits(s, func(w *Window) []string { return w.SecretHits })
	if len(patterns) == 0 {
		return nil
	}
	return []Finding{mk(d, "hit", SeverityHigh, ConfidenceHeuristic,
		"response content matched a secret-shaped pattern",
		fmt.Sprintf("%d distinct pattern(s) matched across %d response(s) — a tool result appears to carry credential-shaped content back toward the client",
			len(patterns), len(windows)),
		append(append([]string{}, patterns...), windows...)...)}
}

// ResponseInjectionPattern reports instruction-shaped phrasing observed
// in a tool response.
//
// §1's fourth principle is that untrusted content is labelled, not
// sanitized. This detector is the observational half of that: it never
// filters what reaches the model (that is the response guard's job, v1),
// it only surfaces, after the fact, that a response read as an
// instruction rather than as data — the shape prompt injection takes.
// Heuristic confidence: a false match must never move a session past
// TierWatch.
type ResponseInjectionPattern struct{}

func (ResponseInjectionPattern) Name() string   { return "response-injection-pattern" }
func (ResponseInjectionPattern) Family() Family { return FamilyProtocol }

func (d ResponseInjectionPattern) Inspect(s *Snapshot) []Finding {
	phrases, windows := collectHits(s, func(w *Window) []string { return w.InjectionHits })
	if len(phrases) == 0 {
		return nil
	}
	return []Finding{mk(d, "hit", SeverityMedium, ConfidenceHeuristic,
		"response content matched an instruction-shaped phrase",
		fmt.Sprintf("%d distinct phrase(s) matched across %d response(s) — content returned to the client reads as an instruction rather than as data",
			len(phrases), len(windows)),
		append(append([]string{}, phrases...), windows...)...)}
}

// collectHits gathers the distinct values pick returns across every
// window that has any, plus the labels of the windows they came from.
func collectHits(s *Snapshot, pick func(*Window) []string) (values, windowLabels []string) {
	seen := map[string]bool{}
	labels := map[string]bool{}
	for _, w := range s.AllWindows() {
		if w == nil {
			continue
		}
		hits := pick(w)
		if len(hits) == 0 {
			continue
		}
		label := w.RequestID
		if w.Idle {
			label = "idle"
		}
		labels[label] = true
		for _, h := range hits {
			if !seen[h] {
				seen[h] = true
				values = append(values, h)
			}
		}
	}
	for l := range labels {
		windowLabels = append(windowLabels, l)
	}
	sort.Strings(values)
	sort.Strings(windowLabels)
	return values, windowLabels
}
