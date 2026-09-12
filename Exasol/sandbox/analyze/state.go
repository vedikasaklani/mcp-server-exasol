package analyze

import (
	"time"

	"mcp-warden/sandbox/observe"
)

// maxTrackedPaths bounds how many distinct paths one aggregate keeps.
// A daemon that is supposed to run for weeks cannot hold an unbounded
// set, and the detectors that consume paths all care about *which kinds*
// of path were touched, not about an exhaustive inventory. Overflow is
// counted, never silently dropped.
const maxTrackedPaths = 20000

// maxTrackedDials bounds distinct network destinations per aggregate.
const maxTrackedDials = 2048

// Access aggregates every observed reference to one filesystem path.
type Access struct {
	Path       string     `json:"path"`
	Kind       AccessKind `json:"kind"`
	Opens      int        `json:"opens"`
	Errors     int        `json:"errors"`
	ReadBytes  int64      `json:"read_bytes"`
	WriteBytes int64      `json:"write_bytes"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
}

// AccessKind is how a path was used, as inferred from the syscalls that
// referenced it.
type AccessKind string

const (
	AccessRead  AccessKind = "read"
	AccessWrite AccessKind = "write"
	AccessStat  AccessKind = "stat" // metadata only: never opened for data
	AccessExec  AccessKind = "exec"
)

// Window is everything observed during one attribution interval. Because
// §6.3 serializes tool calls within a container, an interval maps exactly
// to one request — which is what makes per-request attribution exact here
// rather than probabilistic.
//
// One Window per session is special: the idle window, which collects
// everything a server did while no request was in flight. A well-behaved
// MCP server is almost entirely quiet there, so it is the cheapest place
// to notice a server doing work nobody asked for.
type Window struct {
	RequestID string            `json:"request_id"`
	ToolName  string            `json:"tool_name,omitempty"`
	Method    string            `json:"method,omitempty"`
	Args      map[string]string `json:"args,omitempty"`
	Start     time.Time         `json:"start"`
	End       time.Time         `json:"end"`
	Closed    bool              `json:"closed"`
	Idle      bool              `json:"idle,omitempty"`
	// Synthetic marks a window the proxy opened for its own purposes
	// rather than for a caller — chiefly the MCP handshake run against
	// every new container.
	//
	// These windows are analysed like any other (startup is where module
	// loading happens, which is exactly where supply-chain drift shows
	// up) but are excluded from request statistics. Counting a Node
	// runtime's several thousand startup syscalls as "activity nobody
	// asked for", or its several hundred startup paths as a typical
	// request's fan-out, would poison both the idle budget and every
	// statistical baseline.
	Synthetic bool `json:"synthetic,omitempty"`

	Events      int                `json:"events"`
	Syscalls    map[string]int     `json:"syscalls"`
	Errnos      map[string]int     `json:"errnos"`
	Paths       map[string]*Access `json:"-"`
	PathOverflo int                `json:"path_overflow"`

	FileReadBytes  int64 `json:"file_read_bytes"`
	FileWriteBytes int64 `json:"file_write_bytes"`
	NetReadBytes   int64 `json:"net_read_bytes"`
	NetWriteBytes  int64 `json:"net_write_bytes"`

	Dials map[string]int `json:"dials,omitempty"`
	Execs []string       `json:"execs,omitempty"`
	Forks int            `json:"forks"`

	// SensitiveReads records credential-shaped paths this window read
	// successfully, with the time of the first such read. Paired with
	// FirstNetWriteAt it gives the read-then-egress ordering that
	// per-call authorization structurally cannot see (§5.3).
	SensitiveReads  []string  `json:"sensitive_reads,omitempty"`
	FirstSensitive  time.Time `json:"-"`
	FirstNetWriteAt time.Time `json:"-"`

	// Denied records kernel denials attributed to this window.
	Denied []string `json:"denied,omitempty"`

	// SecretHits records the names of credential-shaped patterns matched
	// in a response payload attributed to this window. Never the matched
	// text itself — see patterns.go.
	SecretHits []string `json:"secret_hits,omitempty"`
	// InjectionHits records instruction-shaped phrases matched in a
	// response payload attributed to this window.
	InjectionHits []string `json:"injection_hits,omitempty"`

	ResponseBytes int           `json:"response_bytes"`
	Unsolicited   int           `json:"unsolicited"`
	Failed        bool          `json:"failed"`
	Latency       time.Duration `json:"latency_ns"`
}

func newWindow(reqID string, start time.Time) *Window {
	return &Window{
		RequestID: reqID,
		Start:     start,
		Syscalls:  map[string]int{},
		Errnos:    map[string]int{},
		Paths:     map[string]*Access{},
		Dials:     map[string]int{},
	}
}

// DistinctPaths returns how many distinct paths this window touched — the
// fan-out measure. A tool serving one file touches a handful; a tool
// enumerating a directory tree touches hundreds, which is the difference
// between "read the file you asked for" and "inventory the disk."
func (w *Window) DistinctPaths() int { return len(w.Paths) + w.PathOverflo }

// ErrorCount returns how many observed syscalls in this window failed.
func (w *Window) ErrorCount() int {
	n := 0
	for _, c := range w.Errnos {
		n += c
	}
	return n
}

// SyscallCount returns total observed syscalls in this window.
func (w *Window) SyscallCount() int {
	n := 0
	for _, c := range w.Syscalls {
		n += c
	}
	return n
}

// Duration is how long the window was open. For an in-flight window it
// measures against now.
func (w *Window) Duration() time.Duration {
	if w.Closed {
		return w.End.Sub(w.Start)
	}
	return time.Since(w.Start)
}

func (w *Window) touch(path string, kind AccessKind, at time.Time) *Access {
	a, ok := w.Paths[path]
	if !ok {
		if len(w.Paths) >= maxTrackedPaths {
			w.PathOverflo++
			return nil
		}
		a = &Access{Path: path, Kind: kind, FirstSeen: at}
		w.Paths[path] = a
	}
	// Write intent is the strongest claim about a path and must not be
	// downgraded by a later stat of the same file.
	if kind == AccessWrite || (kind == AccessExec && a.Kind != AccessWrite) {
		a.Kind = kind
	} else if a.Kind == AccessStat && kind == AccessRead {
		a.Kind = AccessRead
	}
	a.LastSeen = at
	return a
}

func (w *Window) dial(sa observe.SockAddr) {
	key := sa.String()
	if _, ok := w.Dials[key]; !ok && len(w.Dials) >= maxTrackedDials {
		return
	}
	w.Dials[key]++
}

// merge folds src into w. Used to maintain the session-wide totals
// aggregate without walking every retained window on each evaluation.
func (w *Window) merge(src *Window) {
	w.Events += src.Events
	for k, v := range src.Syscalls {
		w.Syscalls[k] += v
	}
	for k, v := range src.Errnos {
		w.Errnos[k] += v
	}
	for k, v := range src.Paths {
		a, ok := w.Paths[k]
		if !ok {
			if len(w.Paths) >= maxTrackedPaths {
				w.PathOverflo++
				continue
			}
			cp := *v
			w.Paths[k] = &cp
			continue
		}
		a.Opens += v.Opens
		a.Errors += v.Errors
		a.ReadBytes += v.ReadBytes
		a.WriteBytes += v.WriteBytes
		if v.Kind == AccessWrite {
			a.Kind = AccessWrite
		}
		if v.LastSeen.After(a.LastSeen) {
			a.LastSeen = v.LastSeen
		}
	}
	w.PathOverflo += src.PathOverflo
	w.FileReadBytes += src.FileReadBytes
	w.FileWriteBytes += src.FileWriteBytes
	w.NetReadBytes += src.NetReadBytes
	w.NetWriteBytes += src.NetWriteBytes
	for k, v := range src.Dials {
		if _, ok := w.Dials[k]; !ok && len(w.Dials) >= maxTrackedDials {
			continue
		}
		w.Dials[k] += v
	}
	w.Forks += src.Forks
	w.Unsolicited += src.Unsolicited
	for _, e := range src.Execs {
		w.Execs = appendCapped(w.Execs, e, 64)
	}
	for _, s := range src.SensitiveReads {
		w.SensitiveReads = appendCapped(w.SensitiveReads, s, 64)
	}
	for _, d := range src.Denied {
		w.Denied = appendCapped(w.Denied, d, 64)
	}
	for _, h := range src.SecretHits {
		w.SecretHits = appendCapped(w.SecretHits, h, 32)
	}
	for _, h := range src.InjectionHits {
		w.InjectionHits = appendCapped(w.InjectionHits, h, 32)
	}
}

func appendCapped(dst []string, v string, cap int) []string {
	for _, have := range dst {
		if have == v {
			return dst
		}
	}
	if len(dst) >= cap {
		return dst
	}
	return append(dst, v)
}
