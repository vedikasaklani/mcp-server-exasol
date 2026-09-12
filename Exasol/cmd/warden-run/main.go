// Command warden-run executes a real MCP server under full kernel
// confinement — compiled seccomp policy, declared-path-only mounts, no
// network interfaces, cgroup limits — and reports latency and enforcement
// metrics for the session.
//
// This is the enforcing counterpart to warden-observe. The intended
// workflow is:
//
//	warden-observe -emit-profile srv.json -- <server cmd>   # discover
//	$EDITOR srv.json                                        # review, set approved_by
//	warden-run -profile srv.json -- <server cmd>            # enforce
//
// The middle step is not optional: a profile with no approved_by fails
// validation and warden-run refuses to start (§3.2 step 5).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"time"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/observe"
	"mcp-warden/sandbox/profile"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runsc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden-run:", err)
		os.Exit(1)
	}
}

// sessionMetrics is everything one confined session produced.
type sessionMetrics struct {
	ProfileDigest    string          `json:"profile_digest"`
	SyscallsAllowed  int             `json:"syscalls_allowed"`
	ReadMounts       int             `json:"read_mounts"`
	WriteMounts      int             `json:"write_mounts"`
	CreateLatency    time.Duration   `json:"create_latency_ns"`
	CanaryDenied     bool            `json:"canary_denied"`
	CanaryErrno      int             `json:"canary_errno"`
	Requests         int             `json:"requests"`
	Failures         int             `json:"failures"`
	Unsolicited      int             `json:"unsolicited_messages"`
	RequestLatencies []time.Duration `json:"request_latencies_ns"`
	DestroyLatency   time.Duration   `json:"destroy_latency_ns"`
	FinalState       string          `json:"final_state"`
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-run", flag.ContinueOnError)
	profilePath := fs.String("profile", "", "path to an approved CapabilityProfile JSON (required)")
	probePath := fs.String("probe", "", "path to the built probe binary (required)")
	requestsFile := fs.String("requests", "", "newline-delimited request payloads to send (default: one MCP initialize request)")
	iterations := fs.Int("iterations", 1, "how many times to replay the request set, for latency percentiles")
	reqTimeout := fs.Duration("request-timeout", 30*time.Second, "per-request timeout")
	memLimit := fs.Int64("memory-bytes", 0, "container memory cap (0 = default)")
	pidLimit := fs.Int64("pid-limit", 0, "container process/thread cap (0 = default)")
	asJSON := fs.Bool("json", false, "emit metrics as JSON")
	keepBundles := fs.Bool("keep-bundles", false, "keep the generated OCI bundles for inspection")
	var extraEnv stringList
	fs.Var(&extraEnv, "env", "extra KEY=VALUE environment entry for the confined process (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("no command given; usage: warden-run -profile p.json -probe probe -- <command> [args...]")
	}
	if *profilePath == "" {
		return fmt.Errorf("-profile is required")
	}
	if *probePath == "" {
		return fmt.Errorf("-probe is required (build it: go build -o probe ./sandbox/runtime/runsc/probe)")
	}

	// Loading validates. An unapproved profile fails here, before any
	// container is created — the human review gate is load-bearing, not
	// advisory.
	prof, err := profile.Load(*profilePath)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	policy, err := compile.Session(prof, compile.Options{})
	if err != nil {
		return fmt.Errorf("compile session policy: %w", err)
	}

	requests, err := loadRequests(*requestsFile)
	if err != nil {
		return err
	}

	// Resolve the entrypoint to an absolute path on the host. The profile
	// grants (and therefore mounts) the resolved binary, so the guest must
	// be told to exec that exact path — and it removes any dependence on
	// PATH resolution inside a sandbox whose environment we control.
	if resolved, lookErr := exec.LookPath(command[0]); lookErr == nil {
		command[0] = resolved
	}

	bundleRoot, err := os.MkdirTemp("", "warden-run-")
	if err != nil {
		return fmt.Errorf("create bundle root: %w", err)
	}
	if !*keepBundles {
		defer os.RemoveAll(bundleRoot)
	}
	rootfs, err := os.MkdirTemp("", "warden-rootfs-")
	if err != nil {
		return fmt.Errorf("create rootfs: %w", err)
	}
	defer os.RemoveAll(rootfs)

	limits := runsc.DefaultLimits()
	if *memLimit > 0 {
		limits.MemoryBytes = *memLimit
	}
	if *pidLimit > 0 {
		limits.PIDLimit = *pidLimit
	}

	// A confined container starts with no environment unless one is given.
	// This is the minimum a language runtime needs to function; anything
	// beyond it is an explicit -env, because environment variables are a
	// classic way for secrets to reach a process that shouldn't have them.
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/tmp/scratch",
		"TMPDIR=/tmp/scratch",
	}
	env = append(env, extraEnv...)

	rt := &runsc.Runtime{
		BundleRoot:      bundleRoot,
		Rootfs:          runsc.BundleConfig{RootfsPath: rootfs, Args: command, Env: env},
		ProbeBinaryPath: *probePath,
		Limits:          limits,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	m := &sessionMetrics{
		ProfileDigest:   prof.ImageDigest,
		SyscallsAllowed: len(policy.Seccomp.Syscalls[0].Names),
	}
	for _, r := range policy.Landlock.Rules {
		if r.Access&compile.AccessWrite != 0 {
			m.WriteMounts++
		} else {
			m.ReadMounts++
		}
	}

	sup := runtime.NewEnforcingSupervisor(rt)

	start := time.Now()
	container, err := sup.NewContainer(ctx, policy)
	m.CreateLatency = time.Since(start)
	if err != nil {
		return fmt.Errorf("confine container (this is a hard failure by design — a sandbox that cannot be verified must not run the workload): %w", err)
	}
	// Destroy explicitly (not deferred) before reporting, so DestroyLatency
	// is actually measured before the numbers are printed. A defer here
	// would run after reportMetrics and always report zero.
	destroy := func() {
		if m.DestroyLatency != 0 {
			return
		}
		d := time.Now()
		_ = sup.Destroy(context.Background(), container)
		m.DestroyLatency = time.Since(d)
	}
	defer destroy()

	// The container only reached READY because the canary was denied with
	// EPERM; record what was actually observed rather than asserting it.
	if denial, err := rt.ProbeSyscall(ctx, container.ID(), compile.CanarySyscall); err == nil {
		m.CanaryDenied = denial.Occurred
		m.CanaryErrno = denial.Errno
	}

	for i := 0; i < *iterations; i++ {
		for j, payload := range requests {
			reqStart := time.Now()
			res, err := sup.Execute(ctx, container, runtime.ExecRequest{
				RequestID: fmt.Sprintf("req_%d_%d", i, j),
				Payload:   payload,
				Timeout:   *reqTimeout,
			})
			elapsed := time.Since(reqStart)
			m.Requests++
			m.RequestLatencies = append(m.RequestLatencies, elapsed)
			if err != nil {
				m.Failures++
				fmt.Fprintf(os.Stderr, "request %d/%d failed: %v\n", i, j, err)
				// A failure quarantines the container; further requests
				// would just fail on an illegal state transition.
				m.FinalState = container.State().String()
				destroy()
				return reportMetrics(m, *asJSON)
			}
			m.Unsolicited += len(res.Unsolicited)
		}
	}
	m.FinalState = container.State().String()
	destroy()
	return reportMetrics(m, *asJSON)
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func loadRequests(path string) ([][]byte, error) {
	if path == "" {
		return [][]byte{observe.DefaultMCPInitializeRequest()}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read requests file: %w", err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, []byte(line))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("requests file %s contained no requests", path)
	}
	return out, nil
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func reportMetrics(m *sessionMetrics, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(m)
	}

	fmt.Printf("=== confinement ===\n")
	fmt.Printf("profile digest:    %s\n", m.ProfileDigest)
	fmt.Printf("syscalls allowed:  %d (everything else returns EPERM)\n", m.SyscallsAllowed)
	fmt.Printf("mounts:            %d read-only, %d writable (nothing else exists in the guest)\n", m.ReadMounts, m.WriteMounts)
	fmt.Printf("canary:            denied=%v errno=%d\n", m.CanaryDenied, m.CanaryErrno)
	fmt.Printf("final state:       %s\n", m.FinalState)

	fmt.Printf("\n=== latency ===\n")
	fmt.Printf("container create (incl. gVisor boot + canary verify): %v\n", m.CreateLatency)
	fmt.Printf("container destroy:                                    %v\n", m.DestroyLatency)

	if len(m.RequestLatencies) > 0 {
		sorted := append([]time.Duration{}, m.RequestLatencies...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		var sum time.Duration
		for _, d := range sorted {
			sum += d
		}
		fmt.Printf("\nrequests: %d (%d failed, %d unsolicited messages)\n", m.Requests, m.Failures, m.Unsolicited)
		fmt.Printf("  first (cold): %v\n", m.RequestLatencies[0])
		fmt.Printf("  min:          %v\n", sorted[0])
		fmt.Printf("  p50:          %v\n", percentile(sorted, 0.50))
		fmt.Printf("  p95:          %v\n", percentile(sorted, 0.95))
		fmt.Printf("  p99:          %v\n", percentile(sorted, 0.99))
		fmt.Printf("  max:          %v\n", sorted[len(sorted)-1])
		fmt.Printf("  mean:         %v\n", sum/time.Duration(len(sorted)))

		if len(sorted) > 1 {
			warm := append([]time.Duration{}, m.RequestLatencies[1:]...)
			sort.Slice(warm, func(i, j int) bool { return warm[i] < warm[j] })
			fmt.Printf("\nexcluding the first (cold-start) request:\n")
			fmt.Printf("  p50: %v   p95: %v   p99: %v\n",
				percentile(warm, 0.50), percentile(warm, 0.95), percentile(warm, 0.99))
			fmt.Printf("  (architecture §1 budgets proxy overhead at p50 <15ms / p99 <60ms,\n")
			fmt.Printf("   excluding tool execution — these numbers INCLUDE the server's own\n")
			fmt.Printf("   work, so they are an upper bound on sandbox overhead, not a measure of it.)\n")
		}
	}
	if m.Failures > 0 {
		return fmt.Errorf("%d request(s) failed", m.Failures)
	}
	return nil
}
