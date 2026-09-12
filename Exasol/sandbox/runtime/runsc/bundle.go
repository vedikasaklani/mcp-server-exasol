// Package runsc is the real, gVisor-backed implementation of
// runtime.ContainerRuntime, plus the pure OCI bundle generator it's built
// on. See runtime.go for the CLI-invocation half and its integration test
// (runtime_integration_test.go), which is gated on `runsc` actually being
// present and skips otherwise.
package runsc

import (
	"fmt"
	"sort"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
)

// BundleConfig carries the per-instance details a CompiledPolicy doesn't
// know about: where this container's rootfs lives on disk and what its
// entrypoint is. CompiledPolicy is about what's allowed; BundleConfig is
// about which process and filesystem it's allowed to apply to.
type BundleConfig struct {
	RootfsPath string
	Args       []string
	Env        []string
	Cwd        string

	// ProbeBinaryPath, if set, is the host path to the static probe
	// binary (sandbox/runtime/runsc/probe). It's bind-mounted read-only
	// into every container at ProbeMountPath, regardless of what server
	// image the container is otherwise running, so the canary self-test
	// (runtime.runCanaryCheck, via Runtime.ProbeSyscall) has something to
	// invoke inside the same confined namespaces as the real workload —
	// see design note §4 and §5.
	ProbeBinaryPath string

	// Limits are the cgroup v2 resource caps for this container. The zero
	// value means "no limits", which GenerateSpec rejects for enforcing
	// containers — see Limits.
	Limits Limits

	// WrapWithCanaryShim, when true, replaces Process.Args with an
	// invocation of the mounted probe binary's "init" subcommand, wrapping
	// Args as the real workload it execve()s into only after confirming
	// the canary syscall was denied — see probe/main.go's cmdInit. This is
	// the boot-time enforcement gate from design note §4; it must be true
	// for every enforcing container and false for every learning-mode
	// (unconfined) one, since an unconfined container's canary is
	// expected to succeed and the shim would refuse to start the workload
	// at all. Requires ProbeBinaryPath to be set.
	WrapWithCanaryShim bool
}

// ProbeMountPath is the fixed, reserved path the probe binary is always
// mounted at inside a container. Chosen to be extremely unlikely to
// collide with any real server image's own filesystem layout.
const ProbeMountPath = "/.mcp-warden/probe"

// Limits are the cgroup v2 resource caps applied to a container (§6.1.5:
// "CPU, memory, PID count, and IO. Prevents resource exhaustion as a
// denial-of-service against the host"). Without these, a sandboxed server
// that fork-bombs or allocates without bound takes the host down with it —
// syscall and filesystem confinement say nothing about how *much* of a
// permitted resource a workload may consume.
type Limits struct {
	// MemoryBytes caps the container's memory. Exceeding it gets the
	// workload OOM-killed inside the sandbox rather than pressuring the
	// host.
	MemoryBytes int64
	// CPUQuota is the CPU time in microseconds the container may use per
	// CPUPeriod. Quota 200000 with period 100000 means "two cores' worth".
	CPUQuota  int64
	CPUPeriod uint64
	// PIDLimit caps the number of processes/threads. This is the control
	// that actually stops a fork bomb.
	PIDLimit int64
}

// DefaultLimits are deliberately generous enough to run a real
// language-runtime server (a Node MCP server idles around 60-80MB and
// spawns ~10 threads) while still being a hard ceiling far below what it
// takes to hurt a host.
// MaxBindMounts is the most bind mounts a spec may carry.
//
// It is a measured property of gVisor, not a taste: the sandbox process
// receives one donated descriptor per mount, and past this many it exits
// during boot without logging a reason. The value sits below the observed
// cliff (233 booted, 240 did not, on release-20260817) so that a profile
// generated against one gVisor build still boots against a slightly
// different one.
const MaxBindMounts = 236

func DefaultLimits() Limits {
	return Limits{
		MemoryBytes: 1 << 30, // 1 GiB
		CPUQuota:    200000,  // 2 cores
		CPUPeriod:   100000,
		PIDLimit:    256,
	}
}

func (l Limits) toResources() *specs.LinuxResources {
	res := &specs.LinuxResources{}
	if l.MemoryBytes > 0 {
		limit := l.MemoryBytes
		res.Memory = &specs.LinuxMemory{Limit: &limit}
	}
	if l.CPUQuota > 0 && l.CPUPeriod > 0 {
		quota := l.CPUQuota
		period := l.CPUPeriod
		res.CPU = &specs.LinuxCPU{Quota: &quota, Period: &period}
	}
	if l.PIDLimit > 0 {
		pids := l.PIDLimit
		res.Pids = &specs.LinuxPids{Limit: &pids}
	}
	return res
}

// coalesceMounts removes any path that is already covered by another path
// in the set, so a profile declaring hundreds of individual files under a
// common tree compiles to a handful of directory mounts instead of
// hundreds of overlapping ones. A real Node server's dependency tree
// touches ~600 paths; mounting each individually produces an enormous
// config.json full of nested bind mounts, which is both slow and (where
// mounts nest) ill-defined.
//
// removeCovered drops any path from paths that is covered by an entry in
// by, using the same directory-wise coverage rule as coalesceMounts.
func removeCovered(paths, by []string) []string {
	var kept []string
	for _, p := range paths {
		covered := false
		for _, b := range by {
			if p == b || strings.HasPrefix(p, b+"/") {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	return kept
}

// Coverage is directory-wise, not textual: "/usr/lib" covers
// "/usr/lib/libc.so" but not "/usr/libexec".
func coalesceMounts(paths []string) []string {
	sorted := append([]string{}, paths...)
	sort.Strings(sorted)

	var kept []string
	for _, p := range sorted {
		covered := false
		for _, k := range kept {
			if p == k || strings.HasPrefix(p, k+"/") {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	return kept
}

// GenerateSpec turns a CompiledPolicy plus instance details into a
// complete OCI runtime-spec Spec, ready to be serialized as a bundle's
// config.json.
//
// Filesystem confinement is expressed entirely through Mounts, not
// through policy.Landlock: only paths declared in the profile are ever
// mounted into the container's root, so an undeclared path isn't merely
// access-denied, it doesn't exist for the guest (confirmed empirically:
// an unmounted path returns ENOENT, not EACCES). policy.Landlock.Rules
// still feeds Linux.ReadonlyPaths as belt-and-suspenders, but it does
// nothing on this backend: runtime_integration_test.go's
// TestIntegration_LandlockSelfApplyInsideGuest confirmed gVisor's sentry
// reports Landlock ABI 0 to the guest regardless of what the host kernel
// supports (this host reports ABI 10) — the landlock_* syscalls simply
// aren't implemented for a gVisor guest. Landlock only becomes meaningful
// again under a real-kernel backend (Firecracker, v2).
//
// No network namespace is configured: v0 always runs with
// compile.NetworkModeNone (no interfaces at all), and any declared
// destination is reached through the broker socket bind-mount instead —
// see design note flag #4.
func GenerateSpec(policy *compile.CompiledPolicy, cfg BundleConfig) (*specs.Spec, error) {
	if policy == nil {
		return nil, fmt.Errorf("runsc: policy must not be nil")
	}
	if policy.Seccomp == nil {
		return nil, fmt.Errorf("runsc: policy has no compiled seccomp filter — refusing to generate a spec with no syscall confinement")
	}
	if cfg.RootfsPath == "" {
		return nil, fmt.Errorf("runsc: rootfs path is required")
	}
	if len(cfg.Args) == 0 {
		return nil, fmt.Errorf("runsc: entrypoint args are required")
	}
	if policy.Network.Mode != compile.NetworkModeNone {
		return nil, fmt.Errorf("runsc: unsupported network mode %q — v0 only supports %q", policy.Network.Mode, compile.NetworkModeNone)
	}
	if cfg.WrapWithCanaryShim && cfg.ProbeBinaryPath == "" {
		return nil, fmt.Errorf("runsc: WrapWithCanaryShim requires ProbeBinaryPath to be set")
	}

	var readonly, readwrite []string
	for _, r := range policy.Landlock.Rules {
		switch {
		case r.Access&compile.AccessWrite != 0:
			readwrite = append(readwrite, r.Path)
		case r.Access&compile.AccessRead != 0:
			readonly = append(readonly, r.Path)
		}
	}
	readwrite = coalesceMounts(readwrite)
	// A path already covered by a writable mount must not also be mounted
	// read-only: the two would nest, and which one wins is not something
	// to leave to mount ordering. Write is the stronger grant, so it wins
	// and the read entry is dropped.
	readonly = coalesceMounts(readonly)
	readonly = removeCovered(readonly, readwrite)

	mounts := []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/tmp/scratch", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "size=64m"}},
	}
	if policy.Network.BrokerSocketPath != "" {
		mounts = append(mounts, specs.Mount{
			Destination: "/run/warden/broker.sock",
			Type:        "bind",
			Source:      policy.Network.BrokerSocketPath,
			Options:     []string{"bind", "rw"},
		})
	}
	if cfg.ProbeBinaryPath != "" {
		mounts = append(mounts, specs.Mount{
			Destination: ProbeMountPath,
			Type:        "bind",
			Source:      cfg.ProbeBinaryPath,
			Options:     []string{"bind", "ro"},
		})
	}
	for _, p := range readonly {
		mounts = append(mounts, specs.Mount{Destination: p, Type: "bind", Source: p, Options: []string{"bind", "ro"}})
	}
	for _, p := range readwrite {
		mounts = append(mounts, specs.Mount{Destination: p, Type: "bind", Source: p, Options: []string{"bind", "rw"}})
	}

	// gVisor donates one file descriptor per mount to the sandbox process,
	// and past a few hundred the sandbox dies during boot reporting only
	// "cannot read client sync file: EOF" — no log line, no signal, no
	// indication that the mount count is what did it.
	//
	// Measured on gVisor release-20260817 with a real Node server: 233
	// mounts booted, 240 did not. Refusing here converts a silent death
	// into a diagnosis, which is the whole difference between a bug
	// someone can fix and one they can only re-encounter. Profiles
	// generated by sandbox/observe are fitted to a budget well under this
	// (see observe.DefaultMountBudget); a hand-written profile that is not
	// lands here.
	if len(mounts) > MaxBindMounts {
		return nil, fmt.Errorf("runsc: this profile compiles to %d mounts, past the %d gVisor can boot with — "+
			"gVisor donates one file descriptor per mount and the sandbox dies during startup with no error beyond "+
			"'cannot read client sync file'. Narrow the profile's filesystem grants, or regenerate it with a mount budget "+
			"(observe.ProfileOptions.MountBudget), which collapses the largest directories and reports each widening",
			len(mounts), MaxBindMounts)
	}

	cwd := cfg.Cwd
	if cwd == "" {
		cwd = "/"
	}

	processArgs := cfg.Args
	if cfg.WrapWithCanaryShim {
		processArgs = append([]string{ProbeMountPath, "init", "--"}, cfg.Args...)
	}

	return &specs.Spec{
		Version: "1.0.2",
		Process: &specs.Process{
			Args:            processArgs,
			Env:             cfg.Env,
			Cwd:             cwd,
			NoNewPrivileges: true,
		},
		Root:   &specs.Root{Path: cfg.RootfsPath, Readonly: true},
		Mounts: mounts,
		Linux: &specs.Linux{
			Seccomp:       policy.Seccomp,
			ReadonlyPaths: readonly,
			Resources:     cfg.Limits.toResources(),
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.MountNamespace},
				{Type: specs.NetworkNamespace}, // joined but never populated with interfaces
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
			},
		},
	}, nil
}

// GenerateUnconfinedSpec builds the OCI spec for a learning-mode container
// (§6.4): seccomp in log-only mode (SCMP_ACT_LOG, never SCMP_ACT_ERRNO —
// nothing is denied) and no per-path mount restriction, since the entire
// point of learning mode is to discover which paths a server touches
// before any allowlist exists to restrict it to. The root filesystem is
// writable rather than read-only for the same reason.
//
// This is never wrapped with the canary shim (BundleConfig.WrapWithCanaryShim
// is ignored/forced false): the shim refuses to start the real workload
// unless the canary syscall was denied, which by design never happens
// here. Only sandbox/learning may call the code path that reaches this
// function — see that package's doc comment for why that separation is
// structural, not a flag.
func GenerateUnconfinedSpec(cfg BundleConfig) (*specs.Spec, error) {
	if cfg.RootfsPath == "" {
		return nil, fmt.Errorf("runsc: rootfs path is required")
	}
	if len(cfg.Args) == 0 {
		return nil, fmt.Errorf("runsc: entrypoint args are required")
	}

	mounts := []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/tmp/scratch", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "size=64m"}},
	}
	if cfg.ProbeBinaryPath != "" {
		mounts = append(mounts, specs.Mount{
			Destination: ProbeMountPath,
			Type:        "bind",
			Source:      cfg.ProbeBinaryPath,
			Options:     []string{"bind", "ro"},
		})
	}

	cwd := cfg.Cwd
	if cwd == "" {
		cwd = "/"
	}

	return &specs.Spec{
		Version: "1.0.2",
		Process: &specs.Process{
			Args:            cfg.Args,
			Env:             cfg.Env,
			Cwd:             cwd,
			NoNewPrivileges: true,
		},
		Root:   &specs.Root{Path: cfg.RootfsPath, Readonly: false},
		Mounts: mounts,
		Linux: &specs.Linux{
			Seccomp: &specs.LinuxSeccomp{
				DefaultAction: specs.ActLog,
			},
			// Learning mode gives up syscall and path confinement by
			// design (§6.4), but not resource confinement: an unconfined
			// profiling run still must not be able to take the host down.
			Resources: cfg.Limits.toResources(),
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.MountNamespace},
				{Type: specs.NetworkNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
			},
		},
	}, nil
}
