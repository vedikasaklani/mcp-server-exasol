package observe

import (
	"sort"
	"time"
)

// AccessKind is how a path was touched, inferred from the syscall that
// referenced it.
type AccessKind string

const (
	AccessRead    AccessKind = "read"
	AccessWrite   AccessKind = "write"
	AccessUnknown AccessKind = "unknown"
)

// writeIntentSyscalls are syscalls whose path argument implies intent to
// write, as best as can be told from the syscall name alone (not its
// flags — parsing O_WRONLY/O_RDWR out of openat's flags argument would be
// more precise but isn't needed for a first-pass heuristic signal).
var writeIntentSyscalls = map[string]bool{
	"unlink": true, "unlinkat": true, "rename": true, "renameat": true,
	"renameat2": true, "mkdir": true, "mkdirat": true, "creat": true,
	"chmod": true, "fchmod": true, "fchmodat": true, "truncate": true,
	"ftruncate": true, "write": true, "pwrite64": true, "writev": true,
}

// SyscallStat aggregates every observed exit event for one syscall name.
type SyscallStat struct {
	Syscall    string
	Count      int
	ErrorCount int
	TotalTime  time.Duration
	MaxTime    time.Duration
	ErrnosSeen map[string]int // errno name -> count
}

// PathAccess aggregates every observed reference to one filesystem path.
type PathAccess struct {
	Path     string
	Kind     AccessKind
	Count    int
	Syscalls map[string]int
}

// Report is the full observation result for one run: what a process
// actually did, in the shape §3.2 asks a CapabilityProfile candidate to
// be built from, plus the timing data needed to reason about performance.
type Report struct {
	Target        Target
	StartedAt     time.Time
	Duration      time.Duration
	ExitErr       string // empty on a clean exit
	RawEventCount int

	Syscalls map[string]*SyscallStat
	Paths    map[string]*PathAccess
	// NetworkDials are destinations seen in connect/sendto-shaped
	// syscalls. Populated once a syscall referencing a socket address is
	// observed; v0's parser doesn't yet decode sockaddr contents (see
	// BuildReport's doc), so this is currently always empty — kept as a
	// field so heuristics and callers don't need to change shape once it
	// is.
	NetworkDials []string

	RequestLatencies []time.Duration // one per request sent via Target.Requests, in order
}

// SyscallNames returns every observed syscall name, sorted.
func (r *Report) SyscallNames() []string {
	names := make([]string, 0, len(r.Syscalls))
	for n := range r.Syscalls {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// TopSyscallsByTime returns syscall names ordered by total observed time,
// descending, truncated to n (or all of them, if fewer than n).
func (r *Report) TopSyscallsByTime(n int) []*SyscallStat {
	stats := make([]*SyscallStat, 0, len(r.Syscalls))
	for _, s := range r.Syscalls {
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].TotalTime > stats[j].TotalTime })
	if n < len(stats) {
		stats = stats[:n]
	}
	return stats
}

// BuildReport aggregates a raw event stream into a Report. Only Exit
// events carry timing/errno/return-value data, so aggregation is keyed
// off those; Enter events are used only to establish that a call was
// attempted at all (currently redundant with Exit for a process that runs
// to completion, but matters if a syscall's Exit is never observed
// because the process was killed mid-call — e.g. by a future Tetragon
// SIGKILL action in v2).
//
// Path access Kind is inferred only from the syscall name (see
// writeIntentSyscalls), not from open(2)-style flags — a real capability
// profile built from this should be reviewed by a human before being
// promoted to an enforced allowlist (§3.2 step 5), same as any other
// learning-mode output.
func BuildReport(target Target, events []SyscallEvent) *Report {
	r := &Report{
		Target:        target,
		Syscalls:      make(map[string]*SyscallStat),
		Paths:         make(map[string]*PathAccess),
		RawEventCount: len(events),
	}

	for _, ev := range events {
		if ev.Direction != DirExit {
			continue
		}
		st, ok := r.Syscalls[ev.Syscall]
		if !ok {
			st = &SyscallStat{Syscall: ev.Syscall, ErrnosSeen: make(map[string]int)}
			r.Syscalls[ev.Syscall] = st
		}
		st.Count++
		st.TotalTime += ev.Duration
		if ev.Duration > st.MaxTime {
			st.MaxTime = ev.Duration
		}
		if ev.HasErrno {
			st.ErrorCount++
			st.ErrnosSeen[ev.ErrnoName]++
		}

		kind := AccessUnknown
		if writeIntentSyscalls[ev.Syscall] {
			kind = AccessWrite
		} else if ev.Syscall == "openat" || ev.Syscall == "open" || ev.Syscall == "stat" || ev.Syscall == "newfstatat" || ev.Syscall == "access" || ev.Syscall == "readlinkat" {
			kind = AccessRead
		}
		for _, p := range ev.Paths() {
			pa, ok := r.Paths[p]
			if !ok {
				pa = &PathAccess{Path: p, Kind: kind, Syscalls: make(map[string]int)}
				r.Paths[p] = pa
			} else if pa.Kind != kind && kind != AccessUnknown {
				// Seen with both read and write intent across different
				// syscalls — record it plainly rather than picking one
				// arbitrarily.
				pa.Kind = AccessUnknown
			}
			pa.Count++
			pa.Syscalls[ev.Syscall]++
		}
	}

	return r
}
