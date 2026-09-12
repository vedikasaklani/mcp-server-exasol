package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// mk builds a Finding. FirstSeen/LastSeen are left zero: the engine
// stamps them when merging, so a detector cannot accidentally reset the
// age of a condition that has been true for hours.
func mk(d Detector, key string, sev Severity, conf Confidence, title, detail string, evidence ...string) Finding {
	f := Finding{
		Key:        d.Name() + ":" + key,
		Detector:   d.Name(),
		Family:     d.Family(),
		Severity:   sev,
		Confidence: conf,
		Title:      title,
		Detail:     detail,
		Count:      1,
	}
	f.addEvidence(evidence...)
	return f
}

// SyscallDrift reports syscalls the approved profile does not list.
//
// The interesting part is the split between attempted and succeeded. A
// syscall outside the allowlist that returned EPERM is the system working
// exactly as designed: the kernel refused it and left the error context
// that makes it diagnosable. The same syscall *succeeding* means the
// filter the kernel is enforcing is not the filter the profile describes
// — a confinement gap, which is a far more serious condition than any
// behaviour a server can exhibit.
type SyscallDrift struct{}

func (SyscallDrift) Name() string   { return "syscall-drift" }
func (SyscallDrift) Family() Family { return FamilyConformance }

func (d SyscallDrift) Inspect(s *Snapshot) []Finding {
	if !s.Baseline.HasProfile() {
		return nil
	}
	var succeeded, refused []string
	for name, count := range s.Totals.Syscalls {
		if s.Baseline.AllowsSyscall(name) {
			continue
		}
		denied := s.Totals.Errnos[name+"/operation not permitted"]
		if denied >= count {
			refused = append(refused, fmt.Sprintf("%s x%d (EPERM)", name, count))
		} else {
			succeeded = append(succeeded, fmt.Sprintf("%s x%d (%d succeeded)", name, count, count-denied))
		}
	}
	sort.Strings(succeeded)
	sort.Strings(refused)

	var out []Finding
	if len(succeeded) > 0 {
		out = append(out, mk(d, "succeeded", SeverityCritical, ConfidenceDeterministic,
			"undeclared syscall succeeded",
			fmt.Sprintf("%d syscall(s) outside the approved profile completed successfully — the enforced seccomp filter does not match the profile", len(succeeded)),
			succeeded...))
	}
	if len(refused) > 0 {
		out = append(out, mk(d, "refused", SeverityHigh, ConfidenceDeterministic,
			"undeclared syscall attempted and refused",
			fmt.Sprintf("%d syscall(s) outside the approved profile were attempted; the kernel returned EPERM", len(refused)),
			refused...))
	}
	return out
}

// PathDrift reports filesystem access outside the declared path sets.
//
// Read and write are reported separately and weighted differently,
// because they are different claims. Reading an undeclared path is a
// confinement gap. Writing one is a confinement gap that can persist.
type PathDrift struct{}

func (PathDrift) Name() string   { return "path-drift" }
func (PathDrift) Family() Family { return FamilyConformance }

func (d PathDrift) Inspect(s *Snapshot) []Finding {
	if !s.Baseline.HasProfile() {
		return nil
	}
	var undeclaredWrite, undeclaredRead, probed []string
	for p, a := range s.Totals.Paths {
		// A path the sandbox provides is not a path the profile failed to
		// declare — no profile is permitted to declare it. See
		// IsSandboxProvidedPath.
		if IsSandboxProvidedPath(p) {
			continue
		}
		// A directory that exists only because the profile granted
		// something inside it is not drift. See IsAncestorOfGrant.
		if s.Baseline.IsAncestorOfGrant(p) {
			continue
		}
		switch a.Kind {
		case AccessWrite:
			if !s.Baseline.AllowsWrite(p) {
				undeclaredWrite = append(undeclaredWrite, fmt.Sprintf("%s (%d bytes)", p, a.WriteBytes))
			}
		case AccessRead, AccessExec:
			if s.Baseline.AllowsRead(p) {
				continue
			}
			// An access that only ever failed is a probe, not a read.
			// Both matter; conflating them makes the count meaningless.
			if a.Opens > 0 && a.Errors >= a.Opens && a.ReadBytes == 0 {
				// A failed lookup inside a dependency tree is the module
				// resolver trying candidate locations, which is how module
				// resolution works rather than something a server chose to
				// do. Reporting it means every Node and Python server
				// carries a standing finding, and a finding that is always
				// present is one nobody reads. Probes outside the
				// dependency tree — the ones that indicate a server going
				// looking for something — are still reported.
				if IsModulePath(p) {
					continue
				}
				probed = append(probed, p)
			} else {
				undeclaredRead = append(undeclaredRead, fmt.Sprintf("%s (%d bytes)", p, a.ReadBytes))
			}
		}
	}
	sort.Strings(undeclaredWrite)
	sort.Strings(undeclaredRead)
	sort.Strings(probed)

	var out []Finding
	if len(undeclaredWrite) > 0 {
		out = append(out, mk(d, "write", SeverityCritical, ConfidenceDeterministic,
			"write outside declared paths",
			fmt.Sprintf("%d path(s) were written that the profile does not grant write access to", len(undeclaredWrite)),
			undeclaredWrite...))
	}
	if len(undeclaredRead) > 0 {
		out = append(out, mk(d, "read", SeverityHigh, ConfidenceDeterministic,
			"read outside declared paths",
			fmt.Sprintf("%d path(s) were read that the profile does not grant read access to", len(undeclaredRead)),
			undeclaredRead...))
	}
	if len(probed) > 0 {
		sev := SeverityLow
		if len(probed) > 50 {
			sev = SeverityMedium
		}
		out = append(out, mk(d, "probe", sev, ConfidenceDeterministic,
			"probed undeclared paths",
			fmt.Sprintf("%d undeclared path(s) were looked for and not found — failed access still reveals what the server went looking for", len(probed)),
			probed...))
	}
	return out
}

// NetworkDrift reports connections to destinations the profile does not
// declare. §6.1.4 gives a container no interfaces by default, so under
// full enforcement this should be unreachable — which is exactly why it
// is worth measuring. A dial that succeeds here means the network
// namespace is not what the design says it is.
type NetworkDrift struct{}

func (NetworkDrift) Name() string   { return "network-drift" }
func (NetworkDrift) Family() Family { return FamilyConformance }

func (d NetworkDrift) Inspect(s *Snapshot) []Finding {
	if len(s.Totals.Dials) == 0 {
		return nil
	}
	declared := map[string]bool{}
	for _, n := range s.Baseline.Network {
		declared[n] = true
	}
	var undeclared []string
	for dest, count := range s.Totals.Dials {
		if declared[dest] {
			continue
		}
		// Match on host alone too: a profile declares a host and port,
		// but a resolved address is what the syscall carries.
		host := dest
		if i := strings.LastIndex(dest, ":"); i > 0 {
			host = dest[:i]
		}
		if declared[host] {
			continue
		}
		undeclared = append(undeclared, fmt.Sprintf("%s x%d", dest, count))
	}
	if len(undeclared) == 0 {
		return nil
	}
	sort.Strings(undeclared)
	detail := fmt.Sprintf("%d network destination(s) were dialled that the profile does not declare", len(undeclared))
	if !s.Baseline.NetworkDeclared {
		detail += "; this profile declares no network access at all"
	}
	return []Finding{mk(d, "dial", SeverityCritical, ConfidenceDeterministic,
		"connection to undeclared destination", detail, undeclared...)}
}

// WriteThenExec reports a path that was both written and executed. Write
// access plus execute access on the same file is how code that no human
// reviewed gets to run, regardless of whether either permission was
// individually granted — the two are only dangerous together, so neither
// a read-set nor a write-set review catches it.
type WriteThenExec struct{}

func (WriteThenExec) Name() string   { return "write-then-exec" }
func (WriteThenExec) Family() Family { return FamilyConformance }

func (d WriteThenExec) Inspect(s *Snapshot) []Finding {
	var hits []string
	for _, w := range s.AllWindows() {
		if w == nil {
			continue
		}
		for _, exe := range w.Execs {
			if s.Baseline.AllowsWrite(exe) {
				hits = append(hits, exe)
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return []Finding{mk(d, "exec", SeverityCritical, ConfidenceDeterministic,
		"executed a file from a writable path",
		"a path the profile grants write access to was executed; writable-and-executable is how unreviewed code runs",
		hits...)}
}

// KernelDenial surfaces the denials the supervisor already acted on, so
// the dashboard tells the same story as the audit log. Quarantine happens
// in the runtime; this is the record of why.
type KernelDenial struct{}

func (KernelDenial) Name() string   { return "kernel-denial" }
func (KernelDenial) Family() Family { return FamilyConformance }

func (d KernelDenial) Inspect(s *Snapshot) []Finding {
	if s.Denials == 0 {
		return nil
	}
	var ev []string
	for _, w := range s.CompletedRequests() {
		for _, den := range w.Denied {
			ev = append(ev, w.RequestID+": "+den)
		}
	}
	return []Finding{mk(d, "denials", SeverityHigh, ConfidenceDeterministic,
		"kernel denied a confined operation",
		fmt.Sprintf("%d of %d request(s) hit a kernel denial and had their container quarantined", s.Denials, s.Requests),
		ev...)}
}
