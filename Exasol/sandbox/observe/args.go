package observe

import (
	"regexp"
	"strconv"
	"strings"
)

// SplitArgs splits a strace argument list into its top-level arguments.
// gVisor renders structured arguments inline — sockaddrs as
// "{Family: AF_INET, Addr: 1.2.3.4, Port: 443}", iovecs as bracketed
// lists, string contents as quoted literals — all of which can contain
// commas that are not argument separators. Splitting naively on "," is
// therefore wrong in exactly the cases this package cares most about.
func SplitArgs(raw string) []string {
	var (
		args    []string
		depth   int
		inQuote bool
		esc     bool
		cur     strings.Builder
	)
	for _, r := range raw {
		switch {
		case esc:
			esc = false
		case r == '\\' && inQuote:
			esc = true
		case r == '"':
			inQuote = !inQuote
		case inQuote:
			// fall through to the append below
		case r == '{' || r == '[' || r == '(':
			depth++
		case r == '}' || r == ']' || r == ')':
			depth--
		case r == ',' && depth == 0:
			args = append(args, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	if s := strings.TrimSpace(cur.String()); s != "" || len(args) > 0 {
		args = append(args, s)
	}
	return args
}

// Args returns this event's top-level arguments.
func (e SyscallEvent) Args() []string { return SplitArgs(e.RawArgs) }

// hexArg matches a leading hexadecimal value, which is how gVisor renders
// every scalar argument before any human-readable annotation it can add.
var hexArg = regexp.MustCompile(`^0x([0-9a-fA-F]+)`)

// ArgInt returns argument i interpreted as gVisor's leading hex scalar.
// ok is false when the argument is absent or not scalar-shaped (e.g.
// "AT_FDCWD /some/dir", which is a symbolic constant, not a number).
func (e SyscallEvent) ArgInt(i int) (int64, bool) {
	args := e.Args()
	if i >= len(args) {
		return 0, false
	}
	m := hexArg.FindStringSubmatch(args[i])
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(m[1], 16, 64)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

// FD returns the file descriptor in argument 0, for the many syscalls
// whose first argument is one (read, write, connect, sendto, close,
// ...). Callers are responsible for only asking syscalls where that is
// true; this function cannot tell the difference.
func (e SyscallEvent) FD() (int, bool) {
	v, ok := e.ArgInt(0)
	if !ok || v < 0 {
		return 0, false
	}
	return int(v), true
}

// SockAddr is a network destination decoded from a sockaddr argument.
type SockAddr struct {
	Family string // AF_INET, AF_INET6, AF_UNIX, ...
	Addr   string // dotted-quad, bracketless v6 literal, or unix path
	Port   int
}

// IsNetwork reports whether this address is on an IP family — the only
// families over which data can leave the host.
func (s SockAddr) IsNetwork() bool {
	return s.Family == "AF_INET" || s.Family == "AF_INET6"
}

// String renders the address for display and for use as a map key.
func (s SockAddr) String() string {
	if s.Port > 0 {
		return s.Addr + ":" + strconv.Itoa(s.Port)
	}
	if s.Addr != "" {
		return s.Addr
	}
	return s.Family
}

// sockAddrFields pulls the individual fields out of gVisor's sockaddr
// rendering. Matching per-field rather than as one fixed pattern is
// deliberate: field order and the exact set of fields present vary by
// address family and by runsc version, and a rigid whole-struct regex
// would silently decode nothing the first time either changed. Anything
// that yields a family is better than dropping the event entirely.
var (
	sockFamily = regexp.MustCompile(`Family:\s*(AF_[A-Z0-9_]+)`)
	sockAddrRE = regexp.MustCompile(`Addr:\s*([0-9a-fA-F.:\[\]/_-]+)`)
	sockPortRE = regexp.MustCompile(`Port:\s*(\d+)`)
	sockPathRE = regexp.MustCompile(`Path:\s*"?([^",}]+)"?`)
)

// SockAddr decodes the first sockaddr-shaped argument in this event, as
// found in connect(2), bind(2), sendto(2) and accept(2) traces. ok is
// false when no argument carries a decodable address — which includes
// the legitimate case of a runsc build that renders sockaddrs as bare
// pointers, so callers must degrade rather than assume absence means the
// syscall had no destination.
func (e SyscallEvent) SockAddr() (SockAddr, bool) {
	m := sockFamily.FindStringSubmatch(e.RawArgs)
	if m == nil {
		return SockAddr{}, false
	}
	sa := SockAddr{Family: m[1]}
	if am := sockAddrRE.FindStringSubmatch(e.RawArgs); am != nil {
		sa.Addr = strings.Trim(am[1], "[]")
	}
	if pm := sockPortRE.FindStringSubmatch(e.RawArgs); pm != nil {
		sa.Port, _ = strconv.Atoi(pm[1])
	}
	if sa.Addr == "" {
		if pm := sockPathRE.FindStringSubmatch(e.RawArgs); pm != nil {
			sa.Addr = pm[1]
		}
	}
	return sa, true
}
