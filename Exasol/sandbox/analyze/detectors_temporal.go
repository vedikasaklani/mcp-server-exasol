package analyze

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// IdleActivity reports work done while no request was in flight.
//
// This detector is only possible because of §6.3's serialization rule.
// One in-flight call per container means "no request in flight" is a
// well-defined state rather than a guess, and a server doing substantial
// work in that state is doing work nobody asked for. Timers, background
// refreshes, and beacons all live here.
type IdleActivity struct {
	// Budget is the number of idle syscalls tolerated. Runtimes do some
	// housekeeping — GC, timer wakeups, epoll churn — so this is not zero.
	Budget int
}

func (IdleActivity) Name() string   { return "idle-activity" }
func (IdleActivity) Family() Family { return FamilyTemporal }

// idleBenignSyscalls are the calls a language runtime makes while doing
// nothing. Counting them as suspicious activity would flag every healthy
// server, so they are excluded from the budget rather than from the
// record.
var idleBenignSyscalls = map[string]bool{
	"epoll_wait": true, "epoll_pwait": true, "poll": true, "ppoll": true,
	"futex": true, "nanosleep": true, "clock_nanosleep": true,
	"restart_syscall": true, "rt_sigreturn": true, "sched_yield": true,
	"getpid": true, "gettid": true, "clock_gettime": true, "madvise": true,
	"read": true, "mprotect": true, "mmap": true, "munmap": true,
}

func (d IdleActivity) Inspect(s *Snapshot) []Finding {
	if s.Idle == nil {
		return nil
	}
	budget := d.Budget
	if budget <= 0 {
		budget = 500
	}
	interesting := 0
	var breakdown []string
	for name, n := range s.Idle.Syscalls {
		if idleBenignSyscalls[name] {
			continue
		}
		interesting += n
		breakdown = append(breakdown, fmt.Sprintf("%s x%d", name, n))
	}
	if interesting <= budget {
		return nil
	}
	sort.Strings(breakdown)
	sev := SeverityMedium
	if s.Idle.NetWriteBytes > 0 || len(s.Idle.Dials) > 0 {
		// Idle work that reaches the network is categorically different
		// from idle work that stays local.
		sev = SeverityCritical
	}
	return []Finding{mk(d, "idle", sev, ConfidenceStatistical,
		"activity with no request in flight",
		fmt.Sprintf("%d non-housekeeping syscalls, %d distinct paths and %d bytes of network egress occurred outside any request",
			interesting, s.Idle.DistinctPaths(), s.Idle.NetWriteBytes),
		breakdown...)}
}

// Beaconing reports idle activity that recurs on a regular interval.
//
// Command-and-control traffic is periodic because it polls. Legitimate
// background work is usually either event-driven (irregular) or tied to
// request traffic (attributed to a window, not to idle). So the signal is
// not "the server did something while idle" — that is IdleActivity's job
// — but "the intervals between the things it did are suspiciously
// consistent."
//
// Regularity is measured as the coefficient of variation of the gaps
// between idle bursts. A human-scheduled cron-like task will also look
// regular here, so this is Statistical: it is a reason to look, not a
// verdict.
type Beaconing struct {
	// MinBursts is how many idle bursts are needed before periodicity
	// means anything. Three points can always be fitted to a line.
	MinBursts int
	// MaxCV is the coefficient of variation below which the intervals
	// count as regular.
	MaxCV float64
	// MinInterval ignores bursts closer together than this; sub-second
	// churn is runtime noise, not a beacon.
	MinInterval time.Duration
}

func (Beaconing) Name() string   { return "beaconing" }
func (Beaconing) Family() Family { return FamilyTemporal }

func (d Beaconing) Inspect(s *Snapshot) []Finding {
	minBursts := d.MinBursts
	if minBursts <= 0 {
		minBursts = 6
	}
	maxCV := d.MaxCV
	if maxCV <= 0 {
		maxCV = 0.15
	}
	minInterval := d.MinInterval
	if minInterval <= 0 {
		minInterval = time.Second
	}
	if len(s.IdleBursts) < minBursts {
		return nil
	}

	var gaps []float64
	for i := 1; i < len(s.IdleBursts); i++ {
		g := s.IdleBursts[i].Sub(s.IdleBursts[i-1])
		if g < minInterval {
			continue
		}
		gaps = append(gaps, g.Seconds())
	}
	if len(gaps) < minBursts-1 {
		return nil
	}

	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean <= 0 {
		return nil
	}
	variance := 0.0
	for _, g := range gaps {
		variance += (g - mean) * (g - mean)
	}
	cv := math.Sqrt(variance/float64(len(gaps))) / mean
	if cv > maxCV {
		return nil
	}

	sev := SeverityHigh
	conf := ConfidenceStatistical
	detail := fmt.Sprintf("%d idle bursts spaced %.1fs apart with %.1f%% variation — a regular interval, not event-driven work",
		len(gaps)+1, mean, cv*100)
	if s.Idle != nil && (s.Idle.NetWriteBytes > 0 || len(s.Idle.Dials) > 0) {
		sev = SeverityCritical
		detail += fmt.Sprintf("; these bursts include %d bytes of network egress", s.Idle.NetWriteBytes)
	}
	return []Finding{mk(d, "periodic", sev, conf, "periodic idle activity", detail, dialList(s.Idle)...)}
}

// DurationBudget reports tool calls that exceed the max_duration_ms the
// profile declares for them (§8.2). This is a conformance fact rather
// than a performance opinion: the number came from the profile a human
// approved, not from a threshold this package chose.
type DurationBudget struct{}

func (DurationBudget) Name() string   { return "duration-budget" }
func (DurationBudget) Family() Family { return FamilyTemporal }

func (d DurationBudget) Inspect(s *Snapshot) []Finding {
	if len(s.Baseline.MaxDurationMS) == 0 {
		return nil
	}
	var over []string
	for _, w := range s.CompletedRequests() {
		budget, ok := s.Baseline.MaxDurationMS[w.ToolName]
		if !ok || budget <= 0 || w.Latency == 0 {
			continue
		}
		if w.Latency <= time.Duration(budget)*time.Millisecond {
			continue
		}
		over = append(over, fmt.Sprintf("%s: %v > %dms (request %s)", w.ToolName, w.Latency.Round(time.Millisecond), budget, w.RequestID))
	}
	if len(over) == 0 {
		return nil
	}
	sort.Strings(over)
	return []Finding{mk(d, "exceeded", SeverityMedium, ConfidenceDeterministic,
		"tool call exceeded its declared duration budget",
		fmt.Sprintf("%d call(s) ran longer than the profile's max_duration_ms", len(over)),
		over...)}
}
