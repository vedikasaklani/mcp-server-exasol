package observe

import (
	"fmt"
	"time"
)

// Severity ranks a Finding. It's a closed set on purpose — heuristics
// don't get to invent new severities, so callers can sort/filter/gate on
// it reliably.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
)

// Finding is one heuristic's verdict about one thing it noticed in a
// Report.
type Finding struct {
	Heuristic string
	Severity  Severity
	Message   string
}

// Heuristic evaluates a Report and returns zero or more Findings. This is
// the extension point: sandbox/observe ships a handful of built-ins (see
// DefaultHeuristics), but the type is exported specifically so a caller
// can implement their own — e.g. an organization-specific "this path
// prefix is always sensitive" rule, or a statistical outlier detector
// over RequestLatencies — and run it through the exact same Evaluate
// pipeline.
//
// A Heuristic is advisory, same as every non-deterministic classifier in
// architecture.md's IBAC design (§5.4): it can flag, it cannot block on
// its own. Wiring a Finding to an actual deny decision is a decision for
// whatever calls this package, not something Heuristic itself does.
type Heuristic interface {
	Name() string
	Evaluate(*Report) []Finding
}

// Evaluate runs every heuristic in hs against r and returns all Findings,
// each stamped with its producing heuristic's name.
func Evaluate(r *Report, hs []Heuristic) []Finding {
	var findings []Finding
	for _, h := range hs {
		for _, f := range h.Evaluate(r) {
			f.Heuristic = h.Name()
			findings = append(findings, f)
		}
	}
	return findings
}

// DefaultHeuristics returns a small, conservative built-in set. They're
// intentionally simple — pattern checks over what BuildReport already
// aggregated, not statistical models — because the point of this package
// is to make the observation data available in a shape any heuristic
// (simple or sophisticated) can consume, not to ship a finished detector.
func DefaultHeuristics() []Heuristic {
	return []Heuristic{
		DangerousSyscallHeuristic{},
		SensitivePathHeuristic{},
		HighErrorRateHeuristic{Threshold: 0.5},
		SlowSyscallHeuristic{Threshold: 50 * time.Millisecond},
	}
}

// DangerousSyscallHeuristic flags syscalls that have no legitimate reason
// to appear in an MCP tool server's profile — the same spirit as
// compile.CanarySyscall, but observational rather than enforced.
type DangerousSyscallHeuristic struct{}

func (DangerousSyscallHeuristic) Name() string { return "dangerous-syscall" }

var dangerousSyscalls = map[string]string{
	"reboot":            "can restart or halt the host/guest",
	"ptrace":            "can attach to and control other processes",
	"process_vm_readv":  "can read another process's memory",
	"process_vm_writev": "can write another process's memory",
	"init_module":       "loads a kernel module",
	"finit_module":      "loads a kernel module",
	"delete_module":     "unloads a kernel module",
	"kexec_load":        "replaces the running kernel",
	"mount":             "can alter the filesystem topology",
	"umount2":           "can alter the filesystem topology",
	"pivot_root":        "can alter the filesystem topology",
	"setns":             "can join another process's namespaces",
	"unshare":           "can create new namespaces",
	"bpf":               "can load kernel-level eBPF programs",
	"swapon":            "manages swap devices",
	"swapoff":           "manages swap devices",
}

func (DangerousSyscallHeuristic) Evaluate(r *Report) []Finding {
	var findings []Finding
	for _, name := range r.SyscallNames() {
		if why, ok := dangerousSyscalls[name]; ok {
			st := r.Syscalls[name]
			findings = append(findings, Finding{
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("observed %d call(s) to %q — %s", st.Count, name, why),
			})
		}
	}
	return findings
}

// SensitivePathHeuristic flags access to filesystem paths that commonly
// hold credentials or host secrets, regardless of whether the access
// succeeded — an ENOENT on /etc/shadow still tells you the process went
// looking.
type SensitivePathHeuristic struct{}

func (SensitivePathHeuristic) Name() string { return "sensitive-path" }

// Deliberately specific to credential/secret-shaped locations, not broad
// prefixes like "/home" or "/root" — a server's own installation
// legitimately lives somewhere under a home directory in a dev
// environment, and flagging every file it reads there is exactly the
// kind of noise that drowns out real signal (see the reference
// filesystem-server run this heuristic was tuned against: ~550
// near-duplicate "/home" findings, zero of them meaningful).
var sensitivePathPrefixes = []string{
	"/etc/shadow", "/etc/passwd", "/etc/ssh", "/etc/sudoers",
	"/.ssh/", "/.aws/", "/.kube/", "/.docker/config.json", "/.netrc",
	"/.gnupg/", "/.git-credentials",
	"/proc/1/environ", "/var/run/secrets",
}

func (SensitivePathHeuristic) Evaluate(r *Report) []Finding {
	var findings []Finding
	for path, pa := range r.Paths {
		for _, prefix := range sensitivePathPrefixes {
			if containsPath(path, prefix) {
				findings = append(findings, Finding{
					Severity: SeverityWarn,
					Message:  fmt.Sprintf("%s access to %q (matched sensitive pattern %q, %d call(s))", pa.Kind, path, prefix, pa.Count),
				})
				break
			}
		}
	}
	return findings
}

func containsPath(path, needle string) bool {
	for i := 0; i+len(needle) <= len(path); i++ {
		if path[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// HighErrorRateHeuristic flags syscalls that fail more often than
// Threshold (0..1) of the time. A high failure rate on its own isn't
// evidence of malice, but it's evidence worth a human's attention when
// building a profile — either the profile candidate needs more paths
// declared, or the server is probing for things that aren't there.
type HighErrorRateHeuristic struct{ Threshold float64 }

func (HighErrorRateHeuristic) Name() string { return "high-error-rate" }

func (h HighErrorRateHeuristic) Evaluate(r *Report) []Finding {
	var findings []Finding
	for _, name := range r.SyscallNames() {
		st := r.Syscalls[name]
		if st.Count < 3 {
			continue // too few samples for a rate to mean anything
		}
		rate := float64(st.ErrorCount) / float64(st.Count)
		if rate > h.Threshold {
			findings = append(findings, Finding{
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("%q failed %d/%d calls (%.0f%%): %v", name, st.ErrorCount, st.Count, rate*100, st.ErrnosSeen),
			})
		}
	}
	return findings
}

// SlowSyscallHeuristic flags any single syscall invocation slower than
// Threshold. One slow syscall can be noise (host contention, cold cache);
// this is a coarse signal for "something here might dominate the latency
// budget," not a verdict.
type SlowSyscallHeuristic struct{ Threshold time.Duration }

func (SlowSyscallHeuristic) Name() string { return "slow-syscall" }

func (h SlowSyscallHeuristic) Evaluate(r *Report) []Finding {
	var findings []Finding
	for _, name := range r.SyscallNames() {
		st := r.Syscalls[name]
		if st.MaxTime > h.Threshold {
			findings = append(findings, Finding{
				Severity: SeverityInfo,
				Message:  fmt.Sprintf("%q had a call taking %v (threshold %v)", name, st.MaxTime, h.Threshold),
			})
		}
	}
	return findings
}
