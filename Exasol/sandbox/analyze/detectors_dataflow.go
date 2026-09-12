package analyze

import (
	"fmt"
	"sort"
)

// ReadThenEgress is the detector this whole package exists to make
// possible.
//
// Per-call authorization structurally cannot catch the dominant real
// threat (§5.3): the server reads a sensitive file — allowed — and then
// writes to a socket — also allowed. Neither call is a violation. The
// ordering is. Catching it requires two things this engine has and a
// per-call check does not: byte-level attribution of which descriptor the
// data went to, and exact request attribution, which §6.3's serialization
// guarantee provides.
//
// The finding is Deterministic because every element of it is an observed
// fact: this file was read at this time, these bytes left over a socket
// at this later time, within this one request.
type ReadThenEgress struct{}

func (ReadThenEgress) Name() string   { return "read-then-egress" }
func (ReadThenEgress) Family() Family { return FamilyDataFlow }

func (d ReadThenEgress) Inspect(s *Snapshot) []Finding {
	var out []Finding
	for _, w := range s.AllWindows() {
		if w == nil || w.NetWriteBytes == 0 {
			continue
		}
		if w.FirstSensitive.IsZero() || w.FirstNetWriteAt.IsZero() {
			continue
		}
		if !w.FirstSensitive.Before(w.FirstNetWriteAt) {
			continue
		}
		label := w.RequestID
		if w.Idle {
			label = "idle"
		}
		out = append(out, mk(d, label, SeverityCritical, ConfidenceDeterministic,
			"credential read followed by network egress",
			fmt.Sprintf("request %s read %d credential-shaped path(s) and then sent %d bytes to the network %v later",
				label, len(w.SensitiveReads), w.NetWriteBytes, w.FirstNetWriteAt.Sub(w.FirstSensitive).Round(1e6)),
			append(append([]string{}, w.SensitiveReads...), dialList(w)...)...))
	}
	return out
}

func dialList(w *Window) []string {
	out := make([]string, 0, len(w.Dials))
	for dest, n := range w.Dials {
		out = append(out, fmt.Sprintf("-> %s x%d", dest, n))
	}
	sort.Strings(out)
	return out
}

// EgressVolume reports data leaving over the network in a volume the
// request cannot account for.
//
// The comparison is against the response the client actually received. A
// tool that returns a 200-byte answer while pushing a megabyte out a
// socket is moving data somewhere other than to the caller, and that
// asymmetry holds regardless of what the destination is or whether the
// destination could be decoded.
type EgressVolume struct {
	// MinBytes suppresses findings below this volume, so protocol chatter
	// and DNS-sized traffic do not generate noise.
	MinBytes int64
	// Ratio is how many times the response size the egress must exceed.
	Ratio float64
}

func (EgressVolume) Name() string   { return "egress-volume" }
func (EgressVolume) Family() Family { return FamilyDataFlow }

func (d EgressVolume) Inspect(s *Snapshot) []Finding {
	minBytes := d.MinBytes
	if minBytes <= 0 {
		minBytes = 8192
	}
	ratio := d.Ratio
	if ratio <= 0 {
		ratio = 4
	}
	var out []Finding
	for _, w := range s.AllWindows() {
		if w == nil || w.NetWriteBytes < minBytes {
			continue
		}
		budget := float64(w.ResponseBytes) * ratio
		if w.Idle {
			budget = 0
		}
		if float64(w.NetWriteBytes) <= budget {
			continue
		}
		label := w.RequestID
		sev := SeverityHigh
		if w.Idle {
			label = "idle"
			// Egress with no request in flight has no legitimate
			// explanation in terms of serving a caller.
			sev = SeverityCritical
		}
		out = append(out, mk(d, label, sev, ConfidenceStatistical,
			"network egress exceeds what the response explains",
			fmt.Sprintf("%d bytes sent to the network against a %d-byte response (read %d bytes from disk in the same window)",
				w.NetWriteBytes, w.ResponseBytes, w.FileReadBytes),
			dialList(w)...))
	}
	return out
}

// PathFanout reports a request that touched far more distinct paths than
// its peers.
//
// Fan-out is the cheapest available proxy for the difference between
// "read the file you were asked for" and "inventory the filesystem". It
// is scored against the session's own history using a median-absolute-
// deviation score rather than a fixed threshold, because the normal
// fan-out of an MCP server is entirely server-specific — a filesystem
// server touching forty paths is ordinary, a calculator doing so is not.
type PathFanout struct {
	// MADThreshold is how many median-absolute-deviations above the
	// median counts as an outlier.
	MADThreshold float64
	// MinPaths suppresses findings on requests that touched few paths in
	// absolute terms, however unusual that is relative to a quiet server.
	MinPaths int
}

func (PathFanout) Name() string   { return "path-fanout" }
func (PathFanout) Family() Family { return FamilyDataFlow }

func (d PathFanout) Inspect(s *Snapshot) []Finding {
	if !s.Warm() {
		return nil
	}
	threshold := d.MADThreshold
	if threshold <= 0 {
		threshold = 6
	}
	minPaths := d.MinPaths
	if minPaths <= 0 {
		minPaths = 25
	}
	done := s.CompletedRequests()
	vals := make([]float64, 0, len(done))
	for _, w := range done {
		vals = append(vals, float64(w.DistinctPaths()))
	}
	var out []Finding
	for _, w := range done {
		n := w.DistinctPaths()
		if n < minPaths {
			continue
		}
		score := madScore(float64(n), vals)
		if score < threshold {
			continue
		}
		out = append(out, mk(d, w.RequestID, SeverityMedium, ConfidenceStatistical,
			"request touched an unusual number of paths",
			fmt.Sprintf("request %s touched %d distinct paths; session median is %.0f (%.1f MAD above)",
				w.RequestID, n, median(vals), score),
			topPaths(w, 8)...))
	}
	return out
}

func topPaths(w *Window, n int) []string {
	type kv struct {
		p string
		a *Access
	}
	all := make([]kv, 0, len(w.Paths))
	for p, a := range w.Paths {
		all = append(all, kv{p, a})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].a.Opens != all[j].a.Opens {
			return all[i].a.Opens > all[j].a.Opens
		}
		return all[i].p < all[j].p
	})
	if n > len(all) {
		n = len(all)
	}
	out := make([]string, 0, n)
	for _, e := range all[:n] {
		out = append(out, fmt.Sprintf("%s (%s, %d opens)", e.p, e.a.Kind, e.a.Opens))
	}
	return out
}

// Enumeration reports filesystem probing: a high rate of "no such file"
// on path-taking syscalls.
//
// Directory enumeration and path-guessing both look like this, and both
// are reconnaissance rather than work. The rate matters more than the
// count: every runtime misses files during module resolution, so a flat
// count of ENOENT would fire on a healthy Node server's first second.
type Enumeration struct {
	// MinAttempts is the volume below which a rate is not meaningful.
	MinAttempts int
	// Rate is the ENOENT fraction above which probing is reported.
	Rate float64
}

func (Enumeration) Name() string   { return "enumeration" }
func (Enumeration) Family() Family { return FamilyDataFlow }

var pathProbeSyscalls = []string{"openat", "open", "stat", "lstat", "newfstatat", "statx", "access", "faccessat", "faccessat2"}

func (d Enumeration) Inspect(s *Snapshot) []Finding {
	minAttempts := d.MinAttempts
	if minAttempts <= 0 {
		minAttempts = 200
	}
	rate := d.Rate
	if rate <= 0 {
		rate = 0.6
	}

	// Count misses against paths the server actually went looking for,
	// excluding the module resolver's own search.
	//
	// A module loader finds a dependency by trying candidate locations
	// until one exists, so missing far more often than it hits is not
	// evidence of anything — it is the algorithm. A reference Node server
	// starting up misses 74% of 1227 lookups doing nothing but resolving
	// its own imports, which is above this detector's threshold and was
	// never noticed because, until the strace parser was fixed to read
	// error results at all, this detector saw zero misses and could not
	// fire. Rating that as enumeration would flag every Node and Python
	// server ever loaded.
	//
	// What remains after the exclusion is the interesting shape: a server
	// probing for paths outside its dependency tree, which is
	// reconnaissance rather than module loading.
	misses, considered := 0, 0
	var detail []string
	for p, a := range s.Totals.Paths {
		if a.Errors == 0 && a.Opens == 0 {
			continue
		}
		if IsModulePath(p) || IsSandboxProvidedPath(p) {
			continue
		}
		considered += a.Opens
		if a.Opens > 0 && a.Errors >= a.Opens {
			misses += a.Errors
		}
	}
	if considered < minAttempts || misses == 0 {
		return nil
	}
	got := float64(misses) / float64(considered)
	if got < rate {
		return nil
	}
	for p, a := range s.Totals.Paths {
		if a.Opens > 0 && a.Errors >= a.Opens && !IsModulePath(p) && !IsSandboxProvidedPath(p) {
			detail = append(detail, fmt.Sprintf("%s (%d failed lookups)", p, a.Errors))
		}
	}
	sort.Strings(detail)
	if len(detail) > 12 {
		detail = detail[:12]
	}
	return []Finding{mk(d, "probe-rate", SeverityMedium, ConfidenceStatistical,
		"filesystem enumeration",
		fmt.Sprintf("%.0f%% of %d path lookups outside the dependency tree found nothing (%d misses) — consistent with probing rather than work", got*100, considered, misses),
		detail...)}
}

// CredentialAccess reports successful reads of credential-shaped paths.
//
// Confidence is Heuristic when the profile permits the path — the pattern
// list is a guess about what a path means — and Deterministic when it
// does not, because then the profile violation carries the claim and the
// pattern only explains why it matters more than usual.
type CredentialAccess struct{}

func (CredentialAccess) Name() string   { return "credential-access" }
func (CredentialAccess) Family() Family { return FamilyDataFlow }

func (d CredentialAccess) Inspect(s *Snapshot) []Finding {
	var declared, undeclared []string
	for p, a := range s.Totals.Paths {
		if !IsSensitivePath(p) || a.Kind == AccessStat {
			continue
		}
		entry := fmt.Sprintf("%s (%s, %d bytes)", p, a.Kind, a.ReadBytes+a.WriteBytes)
		if s.Baseline.HasProfile() && !s.Baseline.AllowsRead(p) {
			undeclared = append(undeclared, entry)
		} else {
			declared = append(declared, entry)
		}
	}
	sort.Strings(declared)
	sort.Strings(undeclared)

	var out []Finding
	if len(undeclared) > 0 {
		out = append(out, mk(d, "undeclared", SeverityCritical, ConfidenceDeterministic,
			"credential store accessed outside the profile",
			fmt.Sprintf("%d credential-shaped path(s) outside the declared read set were opened", len(undeclared)),
			undeclared...))
	}
	if len(declared) > 0 {
		out = append(out, mk(d, "declared", SeverityMedium, ConfidenceHeuristic,
			"credential store accessed within the profile",
			fmt.Sprintf("%d credential-shaped path(s) the profile permits were opened — worth confirming the grant was intended", len(declared)),
			declared...))
	}
	return out
}
