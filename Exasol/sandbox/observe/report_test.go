package observe

import (
	"testing"
	"time"
)

func exitEvent(syscall, rawArgs string, dur time.Duration, errno int, errnoName string) SyscallEvent {
	return SyscallEvent{
		Direction: DirExit,
		Syscall:   syscall,
		RawArgs:   rawArgs,
		Duration:  dur,
		HasErrno:  errno != 0,
		Errno:     errno,
		ErrnoName: errnoName,
	}
}

func TestBuildReport_AggregatesCountsAndTiming(t *testing.T) {
	events := []SyscallEvent{
		exitEvent("read", "", 10*time.Microsecond, 0, ""),
		exitEvent("read", "", 30*time.Microsecond, 0, ""),
		exitEvent("read", "", 5*time.Microsecond, 1, "EPERM"),
	}
	r := BuildReport(Target{}, events)

	st := r.Syscalls["read"]
	if st == nil {
		t.Fatalf("expected a stat entry for 'read'")
	}
	if st.Count != 3 {
		t.Errorf("Count = %d, want 3", st.Count)
	}
	if st.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", st.ErrorCount)
	}
	if st.MaxTime != 30*time.Microsecond {
		t.Errorf("MaxTime = %v, want 30µs", st.MaxTime)
	}
	if st.TotalTime != 45*time.Microsecond {
		t.Errorf("TotalTime = %v, want 45µs", st.TotalTime)
	}
	if st.ErrnosSeen["EPERM"] != 1 {
		t.Errorf("ErrnosSeen[EPERM] = %d, want 1", st.ErrnosSeen["EPERM"])
	}
}

func TestBuildReport_IgnoresEnterEvents(t *testing.T) {
	events := []SyscallEvent{
		{Direction: DirEnter, Syscall: "openat"},
	}
	r := BuildReport(Target{}, events)
	if len(r.Syscalls) != 0 {
		t.Fatalf("expected enter-only events to contribute nothing, got %+v", r.Syscalls)
	}
}

func TestBuildReport_ClassifiesPathAccessKind(t *testing.T) {
	events := []SyscallEvent{
		exitEvent("openat", "AT_FDCWD /cwd, 0x1 /var/data/readme.txt, O_RDONLY, 0", 0, 0, ""),
		exitEvent("unlink", "0x1 /var/data/scratch.tmp", 0, 0, ""),
	}
	r := BuildReport(Target{}, events)

	if r.Paths["/var/data/readme.txt"].Kind != AccessRead {
		t.Errorf("readme.txt kind = %v, want read", r.Paths["/var/data/readme.txt"].Kind)
	}
	if r.Paths["/var/data/scratch.tmp"].Kind != AccessWrite {
		t.Errorf("scratch.tmp kind = %v, want write", r.Paths["/var/data/scratch.tmp"].Kind)
	}
}

func TestBuildReport_MixedAccessBecomesUnknown(t *testing.T) {
	events := []SyscallEvent{
		exitEvent("openat", "0x1 /var/data/shared.txt", 0, 0, ""),
		exitEvent("unlink", "0x1 /var/data/shared.txt", 0, 0, ""),
	}
	r := BuildReport(Target{}, events)
	if r.Paths["/var/data/shared.txt"].Kind != AccessUnknown {
		t.Errorf("shared.txt seen with both read and write intent should be Unknown, got %v", r.Paths["/var/data/shared.txt"].Kind)
	}
	if r.Paths["/var/data/shared.txt"].Count != 2 {
		t.Errorf("Count = %d, want 2", r.Paths["/var/data/shared.txt"].Count)
	}
}

func TestReport_TopSyscallsByTime(t *testing.T) {
	events := []SyscallEvent{
		exitEvent("slow", "", 100*time.Millisecond, 0, ""),
		exitEvent("fast", "", 1*time.Millisecond, 0, ""),
		exitEvent("medium", "", 10*time.Millisecond, 0, ""),
	}
	r := BuildReport(Target{}, events)

	top := r.TopSyscallsByTime(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 results, got %d", len(top))
	}
	if top[0].Syscall != "slow" || top[1].Syscall != "medium" {
		t.Fatalf("expected [slow, medium] in order, got [%s, %s]", top[0].Syscall, top[1].Syscall)
	}
}

func TestReport_SyscallNamesIsSorted(t *testing.T) {
	events := []SyscallEvent{
		exitEvent("zzz", "", 0, 0, ""),
		exitEvent("aaa", "", 0, 0, ""),
	}
	r := BuildReport(Target{}, events)
	names := r.SyscallNames()
	if len(names) != 2 || names[0] != "aaa" || names[1] != "zzz" {
		t.Fatalf("SyscallNames() = %v, want sorted [aaa zzz]", names)
	}
}
