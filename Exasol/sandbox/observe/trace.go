// Package observe turns gVisor's own strace/debug log into structured
// data: per-syscall events, file paths touched, network destinations
// dialed, and per-syscall latency — the observation half of §3.2's
// capability profiling that sandbox/learning's confinement machinery
// never had a way to produce. gVisor already implements every syscall the
// guest makes (it IS the guest's kernel), so turning on its built-in
// `-strace -debug -debug-log=...` gives complete, per-syscall visibility
// for free — no ptrace, no eBPF, no external tracer needed.
//
// The log line shape below (package-level doc on ParseLine) was reverse
// engineered against a real runsc release-20260406.0 by capturing actual
// output, not guessed from documentation — see the sandbox design note
// and its integration tests for the same discipline applied to the
// confinement side.
package observe

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Direction is which half of a syscall a line records: the call entering
// the kernel, or the result leaving it. gVisor logs both as separate
// lines; most fields (Errno, ReturnValue, Duration) are only populated on
// Exit.
type Direction string

const (
	DirEnter Direction = "enter"
	DirExit  Direction = "exit"
)

// SyscallEvent is one parsed strace line.
type SyscallEvent struct {
	Time      time.Time
	ThreadGrp int
	ThreadID  int
	Process   string
	Direction Direction
	Syscall   string
	RawArgs   string
	// The following are only set on Exit events.
	ReturnValue int64
	HasErrno    bool
	Errno       int
	ErrnoName   string
	Duration    time.Duration
}

// logLine is the outer JSON envelope every runsc --debug-log-format=json
// line is wrapped in. Only Msg matters here; Level/Time are metadata
// about the log line itself, not the syscall event it may describe.
type logLine struct {
	Msg  string `json:"msg"`
	Time string `json:"time"`
}

// stracePrefix matches "strace.go:<line>] " at the start of a debug log
// message, which every strace-emitted line carries. Non-strace log lines
// (config dumps, spec JSON, lifecycle messages) don't match and are
// skipped by ParseLine.
var stracePrefix = regexp.MustCompile(`^strace\.go:\d+\]\s+`)

// straceHead matches the fixed prefix of a strace message body: thread
// group, thread, process name, direction, syscall name, and the opening
// parenthesis of the argument list.
//
//	[   1:   1] probe E arch_prctl(0x1002, 0x68b908)
//	[   1:   1] node  X openat(AT_FDCWD /, 0x7f.. /etc/ld.so.cache, O_RDONLY, 0o0) = 3 (0x3) (241.769µs)
var straceHead = regexp.MustCompile(`^\[\s*(\d+):\s*(\d+)\]\s+(\S+)\s+([EX])\s+(\w+)\(`)

// straceTail matches the result of an exit line, anchored at the end.
//
// Two shapes occur, and an earlier version of this regex only knew the
// first — which made every failed syscall parse as a successful one
// returning zero:
//
//	... ) = 3 (0x3) (241.769µs)                              success
//	... ) = -1 errno=2 (no such file or directory) (6.355µs) failure
//
// The parenthesised hex form is present only on success, so it must be
// optional. Getting this wrong is not a parse error that announces
// itself: the line still matches, the return value reads as 0 and the
// errno vanishes, so a denied syscall becomes an undeclared syscall that
// "succeeded" — the exact shape of a false confinement-gap alarm — and
// every read's byte count becomes zero.
//
// Anchoring at the end rather than matching the argument list
// non-greedily is what makes this robust to arguments that themselves
// contain a close parenthesis, which read(2) and write(2) routinely do
// once gVisor renders a buffer's contents.
var straceTail = regexp.MustCompile(
	`\)\s*=\s*(-?\d+)(?:\s*\((?:0x)?[0-9a-fA-F]+\))?` +
		`(?:\s*errno=(\d+)\s*\(([^)]*)\))?` +
		`(?:\s*\(([\d.]+(?:ns|µs|ms|s))\))?\s*$`,
)

// pointerDecodedPath matches an argument of the shape "0xHEX /resolved/path"
// — gVisor's strace annotation for a pointer argument it could resolve to
// a filesystem path. This deliberately excludes bare "AT_FDCWD /cwd/path"
// annotations (no hex pointer), which describe openat's directory-fd
// context, not the path actually being opened.
var pointerDecodedPath = regexp.MustCompile(`0x[0-9a-fA-F]+\s+(/[^\s,()]+)`)

// ParseLine parses one line of a runsc --debug-log-format=json log file.
// It returns ok=false for lines that aren't strace events (the large
// majority of the log — config dumps, lifecycle messages) or that don't
// match the expected shape, without treating either as an error: a log
// format this project doesn't fully understand should degrade to "skip
// what we can't parse," not fail the whole run.
func ParseLine(raw string) (SyscallEvent, bool) {
	var ll logLine
	if err := json.Unmarshal([]byte(raw), &ll); err != nil {
		return SyscallEvent{}, false
	}
	body := stracePrefix.FindStringSubmatchIndex(ll.Msg)
	if body == nil {
		return SyscallEvent{}, false
	}
	rest := ll.Msg[body[1]:]

	head := straceHead.FindStringSubmatchIndex(rest)
	if head == nil {
		return SyscallEvent{}, false
	}
	group := func(n int) string {
		if head[2*n] < 0 {
			return ""
		}
		return rest[head[2*n]:head[2*n+1]]
	}

	tgid, _ := strconv.Atoi(group(1))
	tid, _ := strconv.Atoi(group(2))
	ts, _ := time.Parse(time.RFC3339Nano, ll.Time)

	ev := SyscallEvent{
		Time:      ts,
		ThreadGrp: tgid,
		ThreadID:  tid,
		Process:   group(3),
		Syscall:   group(5),
	}

	argsAndTail := rest[head[1]:] // everything after the opening parenthesis
	if group(4) == "E" {
		ev.Direction = DirEnter
		ev.RawArgs = strings.TrimSuffix(strings.TrimSpace(argsAndTail), ")")
		return ev, true
	}
	ev.Direction = DirExit

	tail := straceTail.FindStringSubmatchIndex(argsAndTail)
	if tail == nil {
		// An exit line whose result cannot be read is not a usable exit
		// event: reporting it with a zero return value would claim the
		// syscall succeeded and moved no bytes, which is a statement about
		// the workload that nothing observed.
		return SyscallEvent{}, false
	}
	ev.RawArgs = argsAndTail[:tail[0]]

	tailGroup := func(n int) string {
		if tail[2*n] < 0 {
			return ""
		}
		return argsAndTail[tail[2*n]:tail[2*n+1]]
	}
	if v := tailGroup(1); v != "" {
		ev.ReturnValue, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := tailGroup(2); v != "" {
		ev.HasErrno = true
		ev.Errno, _ = strconv.Atoi(v)
		ev.ErrnoName = tailGroup(3)
	}
	if v := tailGroup(4); v != "" {
		ev.Duration = parseStraceDuration(v)
	}
	return ev, true
}

func parseStraceDuration(s string) time.Duration {
	// Go's time.ParseDuration understands "ns", "µs" (and "us"), "ms",
	// "s" directly, except gVisor's µ is U+00B5 or U+03BC depending on
	// locale/build; normalize both to "us" for ParseDuration's sake.
	s = strings.ReplaceAll(s, "µs", "us")
	s = strings.ReplaceAll(s, "μs", "us")
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// Paths returns every filesystem path this event's arguments reference,
// as gVisor's strace annotation resolved them. Only meaningful (and only
// non-empty) for path-taking syscalls like openat — most syscalls return
// nothing here.
func (e SyscallEvent) Paths() []string {
	matches := pointerDecodedPath.FindAllStringSubmatch(e.RawArgs, -1)
	if len(matches) == 0 {
		return nil
	}
	paths := make([]string, 0, len(matches))
	for _, m := range matches {
		paths = append(paths, m[1])
	}
	return paths
}

// ParseStream reads newline-delimited JSON log lines from r and returns
// every successfully parsed SyscallEvent, in order. Lines that don't
// parse as strace events are silently skipped (see ParseLine).
func ParseStream(r io.Reader) ([]SyscallEvent, error) {
	var events []SyscallEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024) // spec dumps embedded in some lines are large
	for sc.Scan() {
		if ev, ok := ParseLine(sc.Text()); ok {
			events = append(events, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return events, err
	}
	return events, nil
}
