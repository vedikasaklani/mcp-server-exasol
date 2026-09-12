package runsc

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
)

func samplePolicy() *compile.CompiledPolicy {
	epermRet := uint(1)
	return &compile.CompiledPolicy{
		ToolNames: []string{"query_metrics"},
		Seccomp: &specs.LinuxSeccomp{
			DefaultAction:   specs.ActErrno,
			DefaultErrnoRet: &epermRet,
			Syscalls:        []specs.LinuxSyscall{{Names: []string{"read", "write"}, Action: specs.ActAllow}},
		},
		Landlock: compile.LandlockRuleset{
			Rules: []compile.LandlockRule{
				{Path: "/app", Access: compile.AccessRead},
				{Path: "/tmp/scratch", Access: compile.AccessWrite},
			},
		},
		Network: compile.NetworkConfig{
			Mode:             compile.NetworkModeNone,
			BrokerSocketPath: "/run/warden/broker.sock",
		},
	}
}

func TestGenerateSpec_RejectsNilPolicy(t *testing.T) {
	if _, err := GenerateSpec(nil, BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}}); err == nil {
		t.Fatalf("expected error for nil policy")
	}
}

func TestGenerateSpec_RejectsMissingSeccomp(t *testing.T) {
	p := samplePolicy()
	p.Seccomp = nil
	if _, err := GenerateSpec(p, BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}}); err == nil {
		t.Fatalf("expected error for policy with no compiled seccomp filter")
	}
}

func TestGenerateSpec_RejectsMissingRootfs(t *testing.T) {
	if _, err := GenerateSpec(samplePolicy(), BundleConfig{Args: []string{"/bin/server"}}); err == nil {
		t.Fatalf("expected error for missing rootfs path")
	}
}

func TestGenerateSpec_RejectsMissingArgs(t *testing.T) {
	if _, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs"}); err == nil {
		t.Fatalf("expected error for missing entrypoint args")
	}
}

func TestGenerateSpec_RejectsNonNoneNetworkMode(t *testing.T) {
	p := samplePolicy()
	p.Network.Mode = "sandbox"
	if _, err := GenerateSpec(p, BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}}); err == nil {
		t.Fatalf("expected error for a network mode other than none")
	}
}

func TestGenerateSpec_CarriesSeccompThrough(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Linux.Seccomp == nil || spec.Linux.Seccomp.DefaultAction != specs.ActErrno {
		t.Fatalf("compiled seccomp filter not carried into spec.Linux.Seccomp")
	}
}

func TestGenerateSpec_MountsDeclaredPathsWithCorrectAccess(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byDest := map[string]specs.Mount{}
	for _, m := range spec.Mounts {
		byDest[m.Destination] = m
	}

	ro, ok := byDest["/app"]
	if !ok || !contains(ro.Options, "ro") {
		t.Fatalf("/app not mounted read-only: %+v", ro)
	}
	rw, ok := byDest["/tmp/scratch"]
	if !ok || !contains(rw.Options, "rw") {
		t.Fatalf("/tmp/scratch not mounted read-write: %+v", rw)
	}
}

func TestGenerateSpec_UndeclaredPathIsNeverMounted(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, m := range spec.Mounts {
		if m.Destination == "/etc/shadow" {
			t.Fatalf("undeclared path /etc/shadow must never be mounted (default-deny by omission)")
		}
	}
}

func TestGenerateSpec_MountsBrokerSocketWhenDeclared(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, m := range spec.Mounts {
		if m.Destination == "/run/warden/broker.sock" && m.Source == "/run/warden/broker.sock" {
			found = true
		}
	}
	if !found {
		t.Fatalf("broker socket bind-mount not present: %+v", spec.Mounts)
	}
}

func TestGenerateSpec_OmitsBrokerSocketWhenNotDeclared(t *testing.T) {
	p := samplePolicy()
	p.Network.BrokerSocketPath = ""
	spec, err := GenerateSpec(p, BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, m := range spec.Mounts {
		if m.Destination == "/run/warden/broker.sock" {
			t.Fatalf("broker socket should not be mounted when no path is declared")
		}
	}
}

func TestGenerateSpec_RootIsReadOnly(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !spec.Root.Readonly {
		t.Fatalf("root filesystem must be read-only")
	}
}

func TestGenerateSpec_NoNetworkInterfacesConfigured(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{RootfsPath: "/rootfs", Args: []string{"/bin/server"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A network namespace is joined (for isolation) but nothing populates
	// it with interfaces — there is no NetDevices entry and no veth setup
	// anywhere in this package.
	if len(spec.Linux.NetDevices) != 0 {
		t.Fatalf("expected zero network devices, got %+v", spec.Linux.NetDevices)
	}
}

func TestGenerateSpec_CanaryShimWrapsRealArgs(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{
		RootfsPath:         "/rootfs",
		Args:               []string{"/app/server", "--flag"},
		ProbeBinaryPath:    "/host/probe",
		WrapWithCanaryShim: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{ProbeMountPath, "init", "--", "/app/server", "--flag"}
	if len(spec.Process.Args) != len(want) {
		t.Fatalf("Process.Args = %v, want %v", spec.Process.Args, want)
	}
	for i := range want {
		if spec.Process.Args[i] != want[i] {
			t.Fatalf("Process.Args = %v, want %v", spec.Process.Args, want)
		}
	}
}

func TestGenerateSpec_RejectsCanaryShimWithoutProbeBinary(t *testing.T) {
	_, err := GenerateSpec(samplePolicy(), BundleConfig{
		RootfsPath:         "/rootfs",
		Args:               []string{"/app/server"},
		WrapWithCanaryShim: true,
	})
	if err == nil {
		t.Fatalf("expected error when WrapWithCanaryShim is set without ProbeBinaryPath")
	}
}

func TestGenerateSpec_NoShimLeavesArgsUnwrapped(t *testing.T) {
	spec, err := GenerateSpec(samplePolicy(), BundleConfig{
		RootfsPath: "/rootfs",
		Args:       []string{"/app/server", "--flag"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Process.Args) != 2 || spec.Process.Args[0] != "/app/server" {
		t.Fatalf("Process.Args = %v, want unwrapped [/app/server --flag]", spec.Process.Args)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
