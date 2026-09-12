package observe

import "testing"

func TestSplitArgs_RespectsNestedStructures(t *testing.T) {
	// A sockaddr renders with commas inside braces; splitting naively
	// would turn one argument into three and shift every index after it.
	raw := `0x3 socket:[1], 0x7ffd {Family: AF_INET, Addr: 10.0.0.5, Port: 443}, 0x10`
	got := SplitArgs(raw)
	if len(got) != 3 {
		t.Fatalf("got %d args, want 3: %q", len(got), got)
	}
	if got[1] != `0x7ffd {Family: AF_INET, Addr: 10.0.0.5, Port: 443}` {
		t.Errorf("arg 1 = %q", got[1])
	}
}

func TestSplitArgs_RespectsQuotedCommas(t *testing.T) {
	got := SplitArgs(`0x1, 0x55 "hello, world", 0xc`)
	if len(got) != 3 {
		t.Fatalf("got %d args, want 3: %q", len(got), got)
	}
	if got[1] != `0x55 "hello, world"` {
		t.Errorf("arg 1 = %q", got[1])
	}
}

func TestSplitArgs_Empty(t *testing.T) {
	if got := SplitArgs(""); len(got) != 0 {
		t.Fatalf("empty arg list should split to nothing, got %q", got)
	}
}

func TestArgInt_AndFD(t *testing.T) {
	ev := SyscallEvent{RawArgs: `0x1f, 0x7ffd, 0x400`}
	if v, ok := ev.ArgInt(0); !ok || v != 0x1f {
		t.Errorf("ArgInt(0) = %v, %v; want 31, true", v, ok)
	}
	if fd, ok := ev.FD(); !ok || fd != 31 {
		t.Errorf("FD() = %v, %v; want 31, true", fd, ok)
	}
	if _, ok := ev.ArgInt(9); ok {
		t.Errorf("ArgInt past the end must report not-ok")
	}
}

func TestArgInt_RejectsSymbolicConstant(t *testing.T) {
	// openat's first argument is often AT_FDCWD, which is not a number.
	// Reading it as one would silently produce fd 0 — stdin — and
	// misattribute every byte the call moved.
	ev := SyscallEvent{RawArgs: `AT_FDCWD /home/neal, 0x679ab0 /etc/hosts, O_RDONLY|0x0`}
	if _, ok := ev.ArgInt(0); ok {
		t.Errorf("AT_FDCWD must not parse as a scalar")
	}
	if _, ok := ev.FD(); ok {
		t.Errorf("FD() must not invent a descriptor from AT_FDCWD")
	}
}

func TestSockAddr_DecodesIPv4(t *testing.T) {
	ev := SyscallEvent{RawArgs: `0x3 socket:[1], 0x7ffd {Family: AF_INET, Addr: 10.0.0.5, Port: 443}, 0x10`}
	sa, ok := ev.SockAddr()
	if !ok {
		t.Fatalf("expected a decodable sockaddr")
	}
	if sa.Family != "AF_INET" || sa.Addr != "10.0.0.5" || sa.Port != 443 {
		t.Fatalf("decoded %+v", sa)
	}
	if !sa.IsNetwork() {
		t.Errorf("AF_INET must count as a network family")
	}
	if sa.String() != "10.0.0.5:443" {
		t.Errorf("String() = %q", sa.String())
	}
}

func TestSockAddr_DecodesUnixAndIsNotNetwork(t *testing.T) {
	ev := SyscallEvent{RawArgs: `0x4, 0x7ffd {Family: AF_UNIX, Path: "/run/user/1000/bus"}, 0x1a`}
	sa, ok := ev.SockAddr()
	if !ok {
		t.Fatalf("expected a decodable sockaddr")
	}
	if sa.Family != "AF_UNIX" || sa.Addr != "/run/user/1000/bus" {
		t.Fatalf("decoded %+v", sa)
	}
	if sa.IsNetwork() {
		t.Errorf("a unix socket cannot carry data off the host and must not count as network")
	}
}

func TestSockAddr_DegradesOnUndecodableArgument(t *testing.T) {
	// A runsc build that renders sockaddrs as bare pointers must produce
	// "no address decoded", never a wrong one.
	ev := SyscallEvent{RawArgs: `0x3, 0x7ffd2a4c, 0x10`}
	if _, ok := ev.SockAddr(); ok {
		t.Fatalf("a bare pointer must not decode into an address")
	}
}
