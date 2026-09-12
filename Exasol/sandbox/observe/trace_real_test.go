package observe

import "testing"

// The lines below were captured verbatim from a gVisor release-20260817
// trace of a confined Node MCP server. They are here rather than
// hand-written because the shape of a real error line is precisely what
// an earlier version of this parser got wrong: it required the
// parenthesised hex form that only success lines carry, so every failed
// syscall parsed as a successful one that returned zero. Nothing
// announced the mistake — the denied canary simply showed up as an
// undeclared syscall that succeeded, which reads as a confinement gap,
// and every read's byte count was silently zero.
func TestParseLine_RealGVisorOutput(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		syscall   string
		process   string
		ret       int64
		hasErrno  bool
		errno     int
		errnoName string
	}{
		{
			name:      "denied canary syscall",
			line:      `{"msg":"strace.go:608] [   1:   1] probe X reboot(0xfee1dead, 0x28121969, 0x1234567, 0x14de53c1e038) = -1 errno=1 (operation not permitted) (1.012µs)","level":"info","time":"2026-09-11T20:29:31.607185974Z"}`,
			syscall:   "reboot",
			process:   "probe",
			ret:       -1,
			hasErrno:  true,
			errno:     1,
			errnoName: "operation not permitted",
		},
		{
			name:      "missing file",
			line:      `{"msg":"strace.go:602] [   1:   1] probe X access(0x7eb1cbea9720 /etc/ld.so.preload, 0o4) = -1 errno=2 (no such file or directory) (29.727µs)","level":"info","time":"2026-09-11T20:29:31.596898477Z"}`,
			syscall:   "access",
			process:   "probe",
			ret:       -1,
			hasErrno:  true,
			errno:     2,
			errnoName: "no such file or directory",
		},
		{
			name:     "successful openat returns an fd",
			line:     `{"msg":"strace.go:608] [   1:   1] node X openat(AT_FDCWD /, 0x7eb1cbea8491 /etc/ld.so.cache, O_RDONLY|O_CLOEXEC, 0o0) = 3 (0x3) (241.769µs)","level":"info","time":"2026-09-11T20:29:31.597270728Z"}`,
			syscall:  "openat",
			process:  "node",
			ret:      3,
			hasErrno: false,
		},
		{
			name:     "successful close returns zero",
			line:     `{"msg":"strace.go:608] [   1:   1] node X close(0x3 /etc/ld.so.cache) = 0 (0x0) (4.597µs)","level":"info","time":"2026-09-11T20:29:31.597452738Z"}`,
			syscall:  "close",
			process:  "node",
			ret:      0,
			hasErrno: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := ParseLine(tc.line)
			if !ok {
				t.Fatalf("ParseLine returned ok=false")
			}
			if ev.Syscall != tc.syscall || ev.Process != tc.process {
				t.Errorf("syscall/process = %q/%q, want %q/%q", ev.Syscall, ev.Process, tc.syscall, tc.process)
			}
			if ev.Direction != DirExit {
				t.Errorf("direction = %v, want exit", ev.Direction)
			}
			if ev.ReturnValue != tc.ret {
				t.Errorf("ReturnValue = %d, want %d", ev.ReturnValue, tc.ret)
			}
			if ev.HasErrno != tc.hasErrno {
				t.Fatalf("HasErrno = %v, want %v", ev.HasErrno, tc.hasErrno)
			}
			if tc.hasErrno {
				if ev.Errno != tc.errno || ev.ErrnoName != tc.errnoName {
					t.Errorf("errno = %d/%q, want %d/%q", ev.Errno, ev.ErrnoName, tc.errno, tc.errnoName)
				}
			}
		})
	}
}

// A read's return value is its byte count, and gVisor renders the buffer
// contents into the argument list — parentheses and all. Matching the
// result at the end of the line rather than the arguments non-greedily is
// what keeps the byte count correct here.
func TestParseLine_ArgumentsContainingParentheses(t *testing.T) {
	line := `{"msg":"strace.go:608] [   1:   1] node X read(0x14 /app/data.txt, 0x7f00 \"value (1) and (2)\", 0x1000) = 17 (0x11) (12.5µs)","level":"info","time":"2026-09-11T20:29:31.597452738Z"}`
	ev, ok := ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine returned ok=false")
	}
	if ev.Syscall != "read" {
		t.Fatalf("syscall = %q, want read", ev.Syscall)
	}
	if ev.ReturnValue != 17 {
		t.Errorf("ReturnValue = %d, want 17 (byte counts drive every data-flow detector)", ev.ReturnValue)
	}
}

func TestIsNotification(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, true},
		{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, false},
		{`{"jsonrpc":"2.0","id":null,"method":"x"}`, true},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, false},
		{`not json at all`, false},
	}
	for _, tc := range cases {
		if got := isNotification([]byte(tc.payload)); got != tc.want {
			t.Errorf("isNotification(%s) = %v, want %v", tc.payload, got, tc.want)
		}
	}
}
