package analyze

import "time"

// Evaluate runs every detector against a fresh snapshot, merges the
// results into the session's finding set, and returns the current set.
//
// Detectors are re-run over the whole session rather than once per
// closed window, and findings are merged by key rather than appended.
// Both choices follow from the same constraint: gVisor writes its debug
// log asynchronously, so events belonging to a request can arrive after
// that request has returned. A "score it once when the window closes"
// design would systematically miss whatever arrived late — which, for a
// server doing something at the end of a call, is exactly the evidence
// that matters. Re-evaluating is idempotent because merging is.
func (e *Engine) Evaluate() []Finding {
	snap := e.Snapshot()

	e.mu.Lock()
	now := e.now()
	e.lastEvalAt = now
	var raised []Finding
	for _, d := range e.detectors {
		for _, f := range d.Inspect(snap) {
			if merged, isNew := e.mergeFindingLocked(f, now); isNew {
				raised = append(raised, merged)
			}
		}
	}
	out := e.findingsLocked()
	onFinding := e.opts.OnFinding
	e.mu.Unlock()

	// Callbacks run outside the lock: the audit log does file I/O, and
	// blocking ingestion behind a disk write would let the tailer's
	// buffer overflow and drop the very events being audited.
	if onFinding != nil {
		for _, f := range raised {
			onFinding(f)
		}
	}
	return out
}

// mergeFindingLocked folds f into the session's finding set. It reports
// isNew for a key never seen before, or for one whose severity has
// escalated — those are the two cases worth waking someone for. A repeat
// of an unchanged condition updates counts and evidence silently.
func (e *Engine) mergeFindingLocked(f Finding, now time.Time) (Finding, bool) {
	existing, ok := e.findings[f.Key]
	if !ok {
		f.FirstSeen = now
		f.LastSeen = now
		cp := f
		e.findings[f.Key] = &cp
		return cp, true
	}

	escalated := f.Severity.Rank() > existing.Severity.Rank()
	existing.Count++
	existing.LastSeen = now
	existing.Detail = f.Detail
	existing.addEvidence(f.Evidence...)
	if escalated {
		existing.Severity = f.Severity
		existing.Confidence = f.Confidence
		existing.Title = f.Title
	}
	return *existing, escalated
}

func (e *Engine) findingsLocked() []Finding {
	out := make([]Finding, 0, len(e.findings))
	for _, f := range e.findings {
		out = append(out, *f)
	}
	SortFindings(out)
	return out
}

// Findings returns the current finding set without re-running detectors.
func (e *Engine) Findings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.findingsLocked()
}

// ObserveResponse inspects a response payload for protocol-layer
// conditions that are only visible at the moment the message passes
// through: the tool manifest, which exists in exactly one response and
// must be pinned there (§4.2 step 3), and credential- or
// instruction-shaped content in what should be inert data (§1 principle
// 4). It runs on the request path (see pool.Observer), so both scans are
// bounded — see maxScanBytes.
func (e *Engine) ObserveResponse(payload []byte) {
	hash, hasManifest := HashManifest(payload)
	text := string(payload)
	secretHits := scanSecrets(text)
	injectionHits := scanInjectionPhrases(text)

	if !hasManifest && len(secretHits) == 0 && len(injectionHits) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if hasManifest {
		switch {
		case e.manifestHash == "":
			e.manifestHash = hash
		case e.manifestHash == hash:
			// Stable. Re-advertising an identical manifest is normal.
		default:
			// Record the drift rather than overwriting the pin: overwriting
			// would make the second change look like the first, and a server
			// that mutates its manifest repeatedly is worse, not fixed.
			e.manifestHash = "DRIFT " + e.manifestHash + " -> " + hash
		}
	}

	if len(secretHits) == 0 && len(injectionHits) == 0 {
		return
	}
	w := e.open
	if w == nil {
		w = e.idle
	}
	for _, h := range secretHits {
		w.SecretHits = appendCapped(w.SecretHits, h, 32)
	}
	for _, h := range injectionHits {
		w.InjectionHits = appendCapped(w.InjectionHits, h, 32)
	}
}
