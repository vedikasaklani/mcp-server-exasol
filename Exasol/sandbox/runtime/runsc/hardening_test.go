package runsc

import (
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
)

func TestCoalesceMounts_DropsPathsCoveredByAnAncestor(t *testing.T) {
	got := coalesceMounts([]string{
		"/usr/lib",
		"/usr/lib/libc.so.6",
		"/usr/lib/libm.so.6",
		"/usr/bin/node",
	})
	want := []string{"/usr/bin/node", "/usr/lib"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("coalesceMounts = %v, want %v", got, want)
	}
}

func TestCoalesceMounts_CoverageIsDirectoryWiseNotTextual(t *testing.T) {
	got := coalesceMounts([]string{"/usr/lib", "/usr/libexec"})
	if len(got) != 2 {
		t.Fatalf("coalesceMounts = %v, want both kept — /usr/lib must not swallow /usr/libexec", got)
	}
}

func TestCoalesceMounts_DedupesExactDuplicates(t *testing.T) {
	got := coalesceMounts([]string{"/app", "/app", "/app"})
	if len(got) != 1 {
		t.Fatalf("coalesceMounts = %v, want a single /app", got)
	}
}

func TestRemoveCovered_WriteMountWinsOverNestedReadMount(t *testing.T) {
	readonly := removeCovered([]string{"/data/sub/file.txt", "/etc/ssl"}, []string{"/data"})
	want := []string{"/etc/ssl"}
	if strings.Join(readonly, ",") != strings.Join(want, ",") {
		t.Fatalf("removeCovered = %v, want %v — a path under a writable mount must not also be mounted read-only", readonly, want)
	}
}

func TestGenerateSpec_CoalescesManyPathsIntoFewMounts(t *testing.T) {
	p := samplePolicy()
	p.Landlock.Rules = nil
	// Simulate a real dependency tree: many files under one root.
	for _, f := range []string{"a.js", "b.js", "c/d.js", "c/e.js", "f/g/h.js"} {
		p.Landlock.Rules = append(p.Landlock.Rules, compile.LandlockRule{
			Path: "/srv/app/" + f, Access: compile.AccessRead,
		})
	}
	p.Landlock.Rules = append(p.Landlock.Rules, compile.LandlockRule{Path: "/srv/app", Access: compile.AccessRead})

	spec, err := GenerateSpec(p, BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	appMounts := 0
	for _, m := range spec.Mounts {
		if strings.HasPrefix(m.Destination, "/srv/app") {
			appMounts++
		}
	}
	if appMounts != 1 {
		t.Fatalf("expected the 6 declared paths under /srv/app to coalesce to 1 mount, got %d", appMounts)
	}
}

func TestGenerateSpec_AppliesCgroupLimits(t *testing.T) {
	limits := Limits{MemoryBytes: 512 << 20, CPUQuota: 100000, CPUPeriod: 100000, PIDLimit: 64}
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{
		RootfsPath: "/rootfs", Args: []string{"/bin/server"}, Limits: limits,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res := spec.Linux.Resources
	if res == nil {
		t.Fatalf("expected cgroup resources to be set (§6.1.5)")
	}
	if res.Memory == nil || *res.Memory.Limit != 512<<20 {
		t.Errorf("memory limit not applied: %+v", res.Memory)
	}
	if res.CPU == nil || *res.CPU.Quota != 100000 {
		t.Errorf("cpu quota not applied: %+v", res.CPU)
	}
	if res.Pids == nil || *res.Pids.Limit != 64 {
		t.Errorf("pid limit not applied — this is the control that stops a fork bomb: %+v", res.Pids)
	}
}

func TestGenerateUnconfinedSpec_StillAppliesResourceLimits(t *testing.T) {
	spec, err := GenerateUnconfinedSpec(BundleConfig{
		RootfsPath: "/rootfs", Args: []string{"/bin/server"}, Limits: DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Linux.Resources == nil || spec.Linux.Resources.Pids == nil {
		t.Fatalf("learning mode gives up syscall confinement, not resource confinement")
	}
	if spec.Linux.Seccomp.DefaultAction != specs.ActLog {
		t.Fatalf("unconfined spec must use log-only seccomp, got %v", spec.Linux.Seccomp.DefaultAction)
	}
}

func TestDefaultLimits_AreNonZeroOnEveryAxis(t *testing.T) {
	l := DefaultLimits()
	if l.MemoryBytes <= 0 || l.CPUQuota <= 0 || l.CPUPeriod == 0 || l.PIDLimit <= 0 {
		t.Fatalf("every limit axis must have a real default, got %+v", l)
	}
}

func TestJSONRPCID_ExtractsNumericAndStringIDs(t *testing.T) {
	if id, ok := jsonRPCID([]byte(`{"jsonrpc":"2.0","id":7,"method":"x"}`)); !ok || id != "7" {
		t.Errorf("numeric id = (%q, %v), want (7, true)", id, ok)
	}
	if id, ok := jsonRPCID([]byte(`{"jsonrpc":"2.0","id":"abc","result":{}}`)); !ok || id != `"abc"` {
		t.Errorf("string id = (%q, %v), want (\"abc\", true)", id, ok)
	}
}

func TestJSONRPCID_TreatsNotificationsAsHavingNoID(t *testing.T) {
	if _, ok := jsonRPCID([]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`)); ok {
		t.Errorf("a notification has no id and must not report one")
	}
	if _, ok := jsonRPCID([]byte(`{"jsonrpc":"2.0","id":null,"method":"x"}`)); ok {
		t.Errorf("a null id must not be treated as a real id")
	}
	if _, ok := jsonRPCID([]byte(`not json at all`)); ok {
		t.Errorf("non-JSON payload must not report an id")
	}
}

func TestTraceDir_ReportsNothingWhenTracingIsOffOrDropped(t *testing.T) {
	r := &Runtime{BundleRoot: "/tmp/bundles"}
	if _, ok := r.TraceDir("c1"); ok {
		t.Fatalf("a Runtime with Trace unset must report no trace directory")
	}

	r.Trace = true
	dir, ok := r.TraceDir("c1")
	if !ok {
		t.Fatalf("tracing is on; a directory must be reported")
	}
	if strings.HasPrefix(dir, "/tmp/bundles/c1") {
		t.Errorf("the trace directory must live outside the OCI bundle, got %q", dir)
	}

	// Once tracing has been abandoned, the analyzer must be told there is
	// nothing to read rather than tailing an empty directory forever and
	// reporting a clean session it never observed.
	r.traceOff.Store(true)
	if _, ok := r.TraceDir("c1"); ok {
		t.Fatalf("tracing was dropped; TraceDir must report that")
	}
}

func TestTraceArgs_DropsTheFilterWhenItIsKnownBad(t *testing.T) {
	root := t.TempDir()
	r := &Runtime{BundleRoot: filepath.Join(root, "bundles"), Trace: true, TraceSyscalls: []string{"openat", "read"}}

	args := strings.Join(r.traceArgs("c1"), " ")
	for _, want := range []string{"-strace", "-debug", "-debug-log-format=json", "-strace-syscalls=openat,read"} {
		if !strings.Contains(args, want) {
			t.Errorf("trace args missing %q: %s", want, args)
		}
	}

	// gVisor treats an unimplemented syscall name in the filter as a
	// fatal boot error, so the filter has to be droppable.
	r.traceFilterOff.Store(true)
	args = strings.Join(r.traceArgs("c1"), " ")
	if strings.Contains(args, "-strace-syscalls") {
		t.Errorf("a filter proven unusable must not be passed again: %s", args)
	}
	if !strings.Contains(args, "-strace") {
		t.Errorf("dropping the filter must keep tracing on, just unfiltered: %s", args)
	}

	r.traceOff.Store(true)
	if got := r.traceArgs("c1"); len(got) != 0 {
		t.Errorf("with tracing abandoned there must be no trace flags at all, got %v", got)
	}
}

func TestTraceDegraded_ReportsWhatWasLost(t *testing.T) {
	r := &Runtime{Trace: true, TraceSyscalls: DetectionSyscalls}
	if f, d := r.TraceDegraded(); f || d {
		t.Fatalf("a fresh Runtime has degraded nothing: %v %v", f, d)
	}
	r.traceFilterOff.Store(true)
	if f, d := r.TraceDegraded(); !f || d {
		t.Fatalf("filter drop not reported: %v %v", f, d)
	}
	r.traceOff.Store(true)
	if f, d := r.TraceDegraded(); !f || !d {
		t.Fatalf("tracing drop not reported: %v %v", f, d)
	}
}

func TestDetectionSyscalls_CoverEveryDetectorInput(t *testing.T) {
	// A detector reading a syscall the trace filter never requests sees
	// nothing and reports nothing — a silent coverage hole, which is the
	// worst kind. These are the syscalls sandbox/analyze switches on.
	have := map[string]bool{}
	for _, s := range DetectionSyscalls {
		have[s] = true
	}
	required := []string{
		"socket", "connect", "close", "openat", "read", "write",
		"sendto", "recvfrom", "execve", "clone", "newfstatat", "unlinkat",
	}
	for _, s := range required {
		if !have[s] {
			t.Errorf("DetectionSyscalls is missing %q, which a detector reads", s)
		}
	}
	// And nothing gVisor is known not to implement, which would be fatal
	// at sandbox boot rather than merely unhelpful.
	for _, s := range []string{"openat2", "clone3", "statx", "faccessat2", "kexec_load", "init_module", "bpf"} {
		if have[s] {
			t.Errorf("DetectionSyscalls contains %q; gVisor rejects unimplemented names in -strace-syscalls and fails to boot", s)
		}
	}
}
