package analyze

import (
	"encoding/json"
	"sync"
	"time"

	"mcp-warden/sandbox/observe"
)

// defaultRetainedWindows is how many completed request windows the engine
// keeps for per-request inspection. Session-wide totals are kept forever
// (they are fixed-size aggregates); individual windows are not, because
// their memory cost scales with traffic.
const defaultRetainedWindows = 256

// Options configures an Engine.
type Options struct {
	// RetainWindows is how many completed request windows to keep.
	RetainWindows int
	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
	// OnFinding is called once per newly-raised or newly-escalated
	// finding, never on a repeat of an unchanged one. This is the hook
	// the audit log uses: §7.1 wants detections recorded in a
	// tamper-evident chain, and recording every repeat of the same
	// finding would make the chain grow with traffic rather than with
	// events worth reviewing.
	OnFinding func(Finding)
}

// fdKey identifies a descriptor within a thread group. Descriptors are
// per-process, so keying on the number alone would conflate fd 3 in the
// server with fd 3 in anything it spawns — and "anything it spawned" is
// precisely the case the supply-chain detectors exist to catch.
type fdKey struct {
	tgid int
	fd   int
}

type fdEntry struct {
	path   string
	socket bool
	addr   observe.SockAddr
	known  bool // an address was decoded for this socket
}

// Engine consumes a live syscall stream and maintains the session state
// the detectors read. It is safe for concurrent use: the tailer feeds
// Ingest from one goroutine while the HTTP handlers call Snapshot and
// Evaluate from others.
type Engine struct {
	mu        sync.Mutex
	opts      Options
	baseline  *Baseline
	detectors []Detector

	now func() time.Time

	fds  map[fdKey]*fdEntry
	open *Window
	// pending holds closed windows in time order so a late-arriving event
	// still lands in the window it belongs to. gVisor writes its debug
	// log asynchronously, so an event's arrival order says nothing about
	// when it happened; its timestamp does.
	pending  []*Window
	idle     *Window
	totals   *Window
	findings map[string]*Finding

	started      time.Time
	requests     int
	failures     int
	denials      int
	latencies    []time.Duration
	toolLatency  map[string][]time.Duration
	idleBursts   []time.Time
	lastEventAt  time.Time
	lastEvalAt   time.Time
	manifestHash string
	entrypoint   EntrypointIdentity
	unattributed int

	stats       PipelineStats
	lastIdleAt  time.Time
	ingested    int64
	idleBurstOn bool
}

// idleBurstGap is how long the idle window must be quiet before the next
// idle event counts as the start of a new burst rather than a
// continuation of the current one. Beaconing is periodic *bursts*, not
// periodic syscalls, so the gap has to be long enough to group the dozens
// of syscalls one network round trip produces.
const idleBurstGap = 750 * time.Millisecond

// maxIdleBursts bounds the burst history the periodicity detector reads.
const maxIdleBursts = 512

// NewEngine creates an engine that measures against baseline using
// detectors.
func NewEngine(baseline *Baseline, detectors []Detector, opts Options) *Engine {
	if opts.RetainWindows <= 0 {
		opts.RetainWindows = defaultRetainedWindows
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	if baseline == nil {
		baseline = &Baseline{}
	}
	start := nowFn()
	return &Engine{
		opts:        opts,
		baseline:    baseline,
		detectors:   detectors,
		now:         nowFn,
		fds:         map[fdKey]*fdEntry{},
		idle:        newIdleWindow(start),
		totals:      newWindow("", start),
		findings:    map[string]*Finding{},
		started:     start,
		toolLatency: map[string][]time.Duration{},
	}
}

func newIdleWindow(start time.Time) *Window {
	w := newWindow("", start)
	w.Idle = true
	return w
}

// BeginSynthetic opens an attribution window for a proxy-initiated
// exchange such as the MCP handshake.
func (e *Engine) BeginSynthetic(requestID, label string, payload []byte) {
	e.BeginRequest(requestID, label, payload)
	e.mu.Lock()
	if e.open != nil {
		e.open.Synthetic = true
	}
	e.mu.Unlock()
}

// BeginRequest opens an attribution window. Callers must call it
// immediately before handing the request to the container and must pair
// it with EndRequest.
func (e *Engine) BeginRequest(requestID, toolName string, payload []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if e.open != nil {
		// §6.3 says one in-flight call per container. If a caller
		// violates that, attribution is no longer exact, so close the
		// abandoned window rather than silently blending two requests'
		// syscalls together.
		e.closeWindowLocked(e.open, now)
	}
	w := newWindow(requestID, now)
	w.ToolName = toolName
	w.Method, w.Args = describeRequest(payload)
	if w.ToolName == "" {
		w.ToolName = toolNameFromPayload(payload)
	}
	e.open = w
}

// EndRequest closes the current window and records the outcome.
func (e *Engine) EndRequest(requestID string, outcome Outcome) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	w := e.open
	if w == nil || (requestID != "" && w.RequestID != requestID) {
		// Nothing open, or a mismatched pair. Record the outcome against
		// session totals so the reliability score stays honest even when
		// attribution failed.
		e.recordOutcomeLocked(nil, outcome)
		return
	}
	w.ResponseBytes = outcome.ResponseBytes
	w.Unsolicited = outcome.Unsolicited
	w.Failed = outcome.Failed
	w.Latency = outcome.Latency
	w.Synthetic = outcome.Synthetic
	if outcome.Denial != "" {
		w.Denied = appendCapped(w.Denied, outcome.Denial, 64)
	}
	e.closeWindowLocked(w, now)
	e.recordOutcomeLocked(w, outcome)
	e.open = nil
	e.idle.Start = now
}

// Outcome is what the request layer observed about a completed call. It
// is separate from what the syscall stream observed on purpose: one comes
// from the proxy, one from the kernel, and a detector comparing the two
// is only meaningful while they remain independent.
type Outcome struct {
	ResponseBytes int
	Unsolicited   int
	Failed        bool
	Denial        string
	Latency       time.Duration
	ToolName      string
	// Synthetic marks a proxy-initiated exchange (see Window.Synthetic).
	Synthetic bool
}

func (e *Engine) recordOutcomeLocked(w *Window, o Outcome) {
	if o.Synthetic {
		// The handshake is the proxy talking to the server, not a caller
		// being served. Counting it would inflate throughput and dilute
		// the error rate with traffic no client sent.
		return
	}
	e.requests++
	if o.Failed {
		e.failures++
	}
	if o.Denial != "" {
		e.denials++
	}
	if o.Latency > 0 {
		e.latencies = appendBoundedDuration(e.latencies, o.Latency, 4096)
		name := o.ToolName
		if name == "" && w != nil {
			name = w.ToolName
		}
		if name != "" {
			e.toolLatency[name] = appendBoundedDuration(e.toolLatency[name], o.Latency, 1024)
		}
	}
}

func appendBoundedDuration(dst []time.Duration, v time.Duration, max int) []time.Duration {
	if len(dst) < max {
		return append(dst, v)
	}
	copy(dst, dst[1:])
	dst[len(dst)-1] = v
	return dst
}

func (e *Engine) closeWindowLocked(w *Window, at time.Time) {
	w.Closed = true
	w.End = at
	e.pending = append(e.pending, w)
	if len(e.pending) > e.opts.RetainWindows {
		// Fold the evicted window into session totals before dropping it
		// so long-run aggregates never depend on retention depth.
		evicted := e.pending[0]
		e.totals.merge(evicted)
		e.pending = e.pending[1:]
	}
}

// SetManifestHash records the hash of the server's advertised tool
// manifest. §4.3: a manifest that changes mid-session is the rug-pull
// attack, and it is cheap to detect only if the first value is pinned.
func (e *Engine) SetManifestHash(h string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.manifestHash = h
}

// SetEntrypoint records the identity of the code actually started inside
// the container.
func (e *Engine) SetEntrypoint(id EntrypointIdentity) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entrypoint = id
}

// Ingest routes one observed syscall event into the window it belongs to.
func (e *Engine) Ingest(ev observe.SyscallEvent) {
	if ev.Direction != observe.DirExit {
		return
	}
	// warden's own canary shim runs inside the container before the
	// workload does. Its syscalls are this system testing itself, not
	// behaviour of the server being analysed, and attributing them to the
	// server makes every container report the canary's deliberately
	// denied syscall as a deviation from the profile.
	if InfrastructureProcesses[ev.Process] {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastEventAt = e.now()

	e.ingested++
	e.stats.EventsIngested = e.ingested
	e.stats.LastEventAt = e.lastEventAt

	w := e.windowForLocked(ev.Time)
	if w.Idle {
		e.noteIdleBurstLocked(ev.Time)
	}
	w.Events++
	w.Syscalls[ev.Syscall]++
	if ev.HasErrno {
		w.Errnos[ev.Syscall+"/"+ev.ErrnoName]++
	}
	e.applyLocked(w, ev)
}

// windowForLocked picks the attribution target for an event timestamp.
// Selection is by time, not by arrival order, because the sentry's log
// writer and this reader are not synchronised.
func (e *Engine) windowForLocked(at time.Time) *Window {
	if at.IsZero() {
		// No usable timestamp: attribute to whatever is open, which is
		// the best available guess, and count it so the dashboard can
		// show that attribution was degraded.
		e.unattributed++
		if e.open != nil {
			return e.open
		}
		return e.idle
	}
	if e.open != nil && !at.Before(e.open.Start) {
		return e.open
	}
	for i := len(e.pending) - 1; i >= 0; i-- {
		w := e.pending[i]
		if !at.Before(w.Start) && !at.After(w.End) {
			return w
		}
	}
	return e.idle
}

// applyLocked extracts the semantic content of an event: descriptor
// bookkeeping, byte accounting, path access, spawns, and dials.
func (e *Engine) applyLocked(w *Window, ev observe.SyscallEvent) {
	tgid := ev.ThreadGrp
	failed := ev.HasErrno

	switch ev.Syscall {
	case "socket", "socketpair", "accept", "accept4":
		if !failed && ev.ReturnValue >= 0 {
			e.fds[fdKey{tgid, int(ev.ReturnValue)}] = &fdEntry{socket: true}
		}
		return

	case "open", "openat", "openat2", "creat":
		paths := ev.Paths()
		var path string
		if len(paths) > 0 {
			path = paths[len(paths)-1]
		}
		kind := AccessRead
		if ev.Syscall == "creat" {
			kind = AccessWrite
		}
		if path != "" {
			if a := w.touch(path, kind, ev.Time); a != nil {
				a.Opens++
				if failed {
					a.Errors++
				}
			}
			if !failed {
				e.noteSensitiveLocked(w, path, ev.Time)
			}
		}
		if !failed && ev.ReturnValue >= 0 {
			e.fds[fdKey{tgid, int(ev.ReturnValue)}] = &fdEntry{path: path}
		}
		return

	case "close":
		if fd, ok := ev.FD(); ok {
			delete(e.fds, fdKey{tgid, fd})
		}
		return

	case "dup", "dup2", "dup3":
		if fd, ok := ev.FD(); ok && !failed && ev.ReturnValue >= 0 {
			if src, ok := e.fds[fdKey{tgid, fd}]; ok {
				cp := *src
				e.fds[fdKey{tgid, int(ev.ReturnValue)}] = &cp
			}
		}
		return

	case "connect":
		fd, hasFD := ev.FD()
		if sa, ok := ev.SockAddr(); ok {
			if sa.IsNetwork() {
				w.dial(sa)
			}
			if hasFD {
				if ent, ok := e.fds[fdKey{tgid, fd}]; ok {
					ent.socket = true
					ent.addr = sa
					ent.known = true
				} else {
					e.fds[fdKey{tgid, fd}] = &fdEntry{socket: true, addr: sa, known: true}
				}
			}
		} else if hasFD {
			// Address undecodable (see observe.SyscallEvent.SockAddr).
			// The connection still happened, so mark the descriptor as a
			// socket; byte-flow accounting stays correct even when the
			// destination does not.
			if ent, ok := e.fds[fdKey{tgid, fd}]; ok {
				ent.socket = true
			} else {
				e.fds[fdKey{tgid, fd}] = &fdEntry{socket: true}
			}
		}
		return

	case "execve", "execveat":
		if paths := ev.Paths(); len(paths) > 0 {
			w.Execs = appendCapped(w.Execs, paths[0], 64)
			w.touch(paths[0], AccessExec, ev.Time)
		}
		return

	case "clone", "clone3", "fork", "vfork":
		if !failed {
			w.Forks++
		}
		return

	case "stat", "lstat", "newfstatat", "statx", "access", "faccessat", "faccessat2", "readlink", "readlinkat":
		for _, p := range ev.Paths() {
			if a := w.touch(p, AccessStat, ev.Time); a != nil && failed {
				a.Errors++
			}
		}
		return

	case "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat",
		"rmdir", "chmod", "fchmodat", "truncate", "link", "linkat", "symlink", "symlinkat":
		for _, p := range ev.Paths() {
			w.touch(p, AccessWrite, ev.Time)
		}
		return

	case "read", "pread64", "readv", "preadv", "recvfrom", "recvmsg", "recvmmsg":
		e.accountBytesLocked(w, ev, tgid, false)
		return

	case "write", "pwrite64", "writev", "pwritev", "sendto", "sendmsg", "sendmmsg":
		e.accountBytesLocked(w, ev, tgid, true)
		return
	}
}

// socketOnlySyscalls are transfer syscalls that can only ever operate on
// a socket, whatever the descriptor table happens to know.
var socketOnlySyscalls = map[string]bool{
	"sendto": true, "sendmsg": true, "sendmmsg": true,
	"recvfrom": true, "recvmsg": true, "recvmmsg": true,
}

// accountBytesLocked attributes a transfer's byte count to either the
// filesystem or the network side, resolved through the descriptor table.
//
// Resolving through the table rather than through strace's rendering of
// the descriptor argument is deliberate: the table is built from the
// return values of socket(2) and openat(2), which are unambiguous, while
// the rendering is a formatting detail that has no stability guarantee.
func (e *Engine) accountBytesLocked(w *Window, ev observe.SyscallEvent, tgid int, outbound bool) {
	if ev.HasErrno || ev.ReturnValue <= 0 {
		return
	}
	n := ev.ReturnValue
	fd, hasFD := ev.FD()
	ent := (*fdEntry)(nil)
	if hasFD {
		ent = e.fds[fdKey{tgid, fd}]
	}

	// A descriptor table can miss a socket whose creation we never saw —
	// one inherited across a fork, or opened before tracing began. The
	// socket-only syscalls are self-identifying, so they override the
	// table rather than deferring to it.
	isSocket := (ent != nil && ent.socket) || socketOnlySyscalls[ev.Syscall]

	if isSocket {
		if outbound {
			w.NetWriteBytes += n
			if w.FirstNetWriteAt.IsZero() {
				w.FirstNetWriteAt = ev.Time
			}
		} else {
			w.NetReadBytes += n
		}
		if ent != nil && ent.known && ent.addr.IsNetwork() {
			w.dial(ent.addr)
		}
		return
	}

	// stdin/stdout/stderr carry the MCP protocol itself. Counting the
	// JSON-RPC conversation as file I/O would swamp the signal that
	// actually matters — what the server read off disk.
	if hasFD && fd <= 2 {
		return
	}
	if outbound {
		w.FileWriteBytes += n
		if ent != nil && ent.path != "" {
			if a := w.touch(ent.path, AccessWrite, ev.Time); a != nil {
				a.WriteBytes += n
			}
		}
	} else {
		w.FileReadBytes += n
		if ent != nil && ent.path != "" {
			if a := w.touch(ent.path, AccessRead, ev.Time); a != nil {
				a.ReadBytes += n
			}
		}
	}
}

// noteIdleBurstLocked records the start of a cluster of activity that
// happened while no request was in flight.
func (e *Engine) noteIdleBurstLocked(at time.Time) {
	if at.IsZero() {
		return
	}
	if e.lastIdleAt.IsZero() || at.Sub(e.lastIdleAt) > idleBurstGap {
		if len(e.idleBursts) >= maxIdleBursts {
			copy(e.idleBursts, e.idleBursts[1:])
			e.idleBursts = e.idleBursts[:len(e.idleBursts)-1]
		}
		e.idleBursts = append(e.idleBursts, at)
	}
	e.lastIdleAt = at
}

// SetPipelineStats records the health of the trace ingestion path so the
// dashboard can distinguish "this server did nothing suspicious" from
// "we stopped being able to see what this server was doing."
func (e *Engine) SetPipelineStats(s observe.TailStats, tracing bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.EventsDropped = s.Dropped
	e.stats.LinesRead = s.LinesRead
	e.stats.BytesRead = s.BytesRead
	e.stats.LogTruncations = s.Truncations
	e.stats.TracingEnabled = tracing
	e.stats.EventsIngested = e.ingested
	e.stats.LastEventAt = e.lastEventAt
}

// Consume drains a tailer channel into the engine until it closes. Run it
// in its own goroutine; it is the normal way to wire observe.Tailer to
// this package.
func (e *Engine) Consume(events <-chan observe.SyscallEvent) {
	for ev := range events {
		e.Ingest(ev)
	}
}

func (e *Engine) noteSensitiveLocked(w *Window, path string, at time.Time) {
	if !IsSensitivePath(path) {
		return
	}
	w.SensitiveReads = appendCapped(w.SensitiveReads, path, 64)
	if w.FirstSensitive.IsZero() {
		w.FirstSensitive = at
	}
}

// describeRequest extracts the JSON-RPC method and a flattened view of
// the call's scalar arguments. The arguments are what the
// argument/access-mismatch detector compares against the paths actually
// touched — §5.1's "typed extractor declared in the profile, never a
// model," applied after the fact as a check rather than before it as an
// authorization.
func describeRequest(payload []byte) (string, map[string]string) {
	if len(payload) == 0 {
		return "", nil
	}
	var msg struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return "", nil
	}
	args := map[string]string{}
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if len(msg.Params) > 0 {
		_ = json.Unmarshal(msg.Params, &params)
	}
	for k, v := range params.Arguments {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			args[k] = s
			continue
		}
		args[k] = string(v)
	}
	return msg.Method, args
}

func toolNameFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return ""
	}
	if msg.Params.Name != "" {
		return msg.Params.Name
	}
	return msg.Method
}
