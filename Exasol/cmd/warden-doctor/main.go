// Command warden-doctor reproduces the confined-container startup path in
// isolation and reports exactly where it fails.
//
// It exists because "cannot read client sync file: EOF" — which is all
// runsc's frontend says when a sandbox dies during boot — is not a
// diagnosis. This walks the same steps a real load performs (observe,
// generate a profile, compile it, boot a container), stopping at the
// first one that breaks and printing what gVisor itself said, with the
// bundle and logs preserved rather than cleaned up.
//
//	warden-doctor -- node /path/to/server.js
//
// With -rootless it runs runsc unprivileged (--rootless
// --ignore-cgroups), which trades away cgroup limits and network
// isolation but makes the whole path reproducible without root — the
// difference between a bug you can iterate on and one you can only
// observe.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/observe"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runsc"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "\nwarden-doctor:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-doctor", flag.ContinueOnError)
	rootless := fs.Bool("rootless", false, "run runsc with --rootless --ignore-cgroups (no root needed; no cgroup limits, host network)")
	probePath := fs.String("probe", "", "path to the built probe binary (default: built on demand)")
	rollup := fs.Int("rollup", 0, "collapse observed paths to N leading components in the generated profile")
	maxMounts := fs.Int("max-mounts", 0, "after generating the profile, keep only the first N read paths (bisecting a mount-count limit)")
	keep := fs.Bool("keep", true, "keep the bundle and logs for inspection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("usage: warden-doctor [flags] -- <command> [args...]")
	}
	if resolved, err := exec.LookPath(command[0]); err == nil {
		command[0] = resolved
	}

	runscPath := "runsc"
	if *rootless {
		var err error
		runscPath, err = writeRootlessWrapper()
		if err != nil {
			return err
		}
		fmt.Printf("using rootless runsc wrapper: %s\n", runscPath)
	}

	probe := *probePath
	if probe == "" {
		var err error
		probe, err = buildProbe()
		if err != nil {
			return err
		}
	}
	fmt.Printf("probe: %s\n", probe)

	ctx := context.Background()

	// ---- step 1: observe -------------------------------------------------
	fmt.Printf("\n=== 1. learning-mode observation ===\n")
	report, err := observe.Run(ctx, observe.Target{
		Command:     command,
		NetworkMode: "none",
		Requests: [][]byte{
			observe.DefaultMCPInitializeRequest(),
			[]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
			[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`),
		},
	}, observe.RunOptions{RunscPath: runscPath, Timeout: 60 * time.Second, RequestTimeout: 15 * time.Second})
	if err != nil && report == nil {
		return fmt.Errorf("observe: %w", err)
	}
	if len(report.Syscalls) == 0 {
		return fmt.Errorf("observed no syscalls: %s", report.ExitErr)
	}
	fmt.Printf("ok: %d syscalls, %d paths, %v\n", len(report.Syscalls), len(report.Paths), report.Duration.Round(time.Millisecond))

	// ---- step 2: profile -------------------------------------------------
	fmt.Printf("\n=== 2. profile generation ===\n")
	cand, err := observe.GenerateProfile(report, observe.ProfileOptions{ToolName: "doctor", RollupDepth: *rollup})
	if err != nil {
		return fmt.Errorf("generate profile: %w", err)
	}
	cand.Profile.ApprovedBy = "operator:doctor"
	if *maxMounts > 0 && len(cand.Profile.Tools[0].Filesystem.Read) > *maxMounts {
		cand.Profile.Tools[0].Filesystem.Read = cand.Profile.Tools[0].Filesystem.Read[:*maxMounts]
		fmt.Printf("truncated read set to %d paths\n", *maxMounts)
	}
	fmt.Printf("ok: %d syscalls, %d read paths, %d write paths\n",
		len(cand.Profile.Tools[0].Syscalls),
		len(cand.Profile.Tools[0].Filesystem.Read),
		len(cand.Profile.Tools[0].Filesystem.Write))

	// ---- step 3: compile -------------------------------------------------
	fmt.Printf("\n=== 3. policy compilation ===\n")
	policy, err := compile.Session(cand.Profile, compile.Options{})
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Printf("ok: %d syscalls allowed, %d landlock rules\n", len(policy.Seccomp.Syscalls[0].Names), len(policy.Landlock.Rules))

	// ---- step 4: spec ----------------------------------------------------
	fmt.Printf("\n=== 4. OCI spec generation ===\n")
	bundleRoot, err := os.MkdirTemp("", "doctor-bundle-")
	if err != nil {
		return err
	}
	rootfs, err := os.MkdirTemp("", "doctor-rootfs-")
	if err != nil {
		return err
	}
	traceRoot, err := os.MkdirTemp("", "doctor-trace-")
	if err != nil {
		return err
	}

	spec, err := runsc.GenerateSpec(policy, runsc.BundleConfig{
		RootfsPath:         rootfs,
		Args:               command,
		Env:                []string{"PATH=/usr/bin:/bin", "HOME=/tmp/scratch", "TMPDIR=/tmp/scratch"},
		ProbeBinaryPath:    probe,
		WrapWithCanaryShim: true,
		Limits:             runsc.DefaultLimits(),
	})
	if err != nil {
		return fmt.Errorf("generate spec: %w", err)
	}
	fmt.Printf("ok: %d mounts in the spec\n", len(spec.Mounts))
	files, dirs, missing := 0, 0, 0
	for _, m := range spec.Mounts {
		if m.Type != "bind" {
			continue
		}
		info, statErr := os.Stat(m.Source)
		switch {
		case statErr != nil:
			missing++
		case info.IsDir():
			dirs++
		default:
			files++
		}
	}
	fmt.Printf("     bind sources: %d files, %d directories, %d MISSING\n", files, dirs, missing)

	// ---- step 4b: raw boot ----------------------------------------------
	// Boot the spec by invoking runsc directly, outside the Runtime's
	// retry-and-clean-up path. That path is right for production — a
	// container that will not start must not leave debris behind — and
	// exactly wrong for diagnosis, because it deletes the debug log that
	// says why before anyone can read it.
	fmt.Printf("\n=== 4b. raw runsc boot (bundle preserved) ===\n")
	if err := rawBoot(ctx, runscPath, spec, bundleRoot); err != nil {
		fmt.Printf("raw boot failed: %v\n", err)
	}

	// ---- step 5: boot ----------------------------------------------------
	fmt.Printf("\n=== 5. container boot (through the real Runtime) ===\n")
	rt := &runsc.Runtime{
		RunscPath:  runscPath,
		BundleRoot: bundleRoot,
		TraceRoot:  traceRoot,
		Rootfs: runsc.BundleConfig{
			RootfsPath: rootfs,
			Args:       command,
			Env:        []string{"PATH=/usr/bin:/bin", "HOME=/tmp/scratch", "TMPDIR=/tmp/scratch"},
		},
		ProbeBinaryPath: probe,
		Limits:          runsc.DefaultLimits(),
		// Mirror the console's analysis configuration exactly: a harness
		// that boots containers differently from the tool it is meant to
		// diagnose can only reproduce a different bug.
		Trace:         true,
		TraceSyscalls: runsc.DetectionSyscalls,
	}
	sup := runtime.NewEnforcingSupervisor(rt)
	container, err := sup.NewContainer(ctx, policy)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		if *keep {
			fmt.Printf("\nbundle:  %s\ntrace:   %s\nrootfs:  %s\n", bundleRoot, traceRoot, rootfs)
			dumpTrace(traceRoot)
		}
		return fmt.Errorf("container boot failed (see above)")
	}
	fmt.Printf("ok: container %s is confined and READY\n", container.ID())

	res, err := sup.Execute(ctx, container, runtime.ExecRequest{
		RequestID: "doctor-1",
		Payload:   observe.DefaultMCPInitializeRequest(),
		Timeout:   15 * time.Second,
	})
	if err != nil {
		fmt.Printf("FAILED on first request: %v\n", err)
	} else {
		fmt.Printf("ok: initialize returned %d bytes\n", len(res.Payload))
	}
	// Copy the trace before Destroy, which deletes it.
	traceCopy := traceRoot + "-kept"
	_ = exec.Command("cp", "-r", traceRoot, traceCopy).Run()
	fmt.Printf("\ntrace kept at: %s\n", traceCopy)
	_ = sup.Destroy(ctx, container)
	fmt.Printf("\nall steps passed\n")

	if !*keep {
		os.RemoveAll(bundleRoot)
		os.RemoveAll(rootfs)
		os.RemoveAll(traceRoot)
	}
	return nil
}

// rawBoot writes a bundle and runs runsc against it directly, with the
// debug log pointed somewhere it will survive, so the sentry's own
// account of its death is readable.
func rawBoot(ctx context.Context, runscPath string, spec *specs.Spec, bundleRoot string) error {
	dir := filepath.Join(bundleRoot, "raw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// The spec's own Process.Args runs the server directly: the canary
	// shim is the Runtime's concern, and leaving it out here isolates
	// "does this mount topology boot at all" from "does the handshake
	// work".
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o644); err != nil {
		return err
	}

	logPath := filepath.Join(bundleRoot, "raw-debug.log")
	id := fmt.Sprintf("doctor-raw-%d", time.Now().UnixNano())
	args := []string{"-debug", "-debug-log=" + logPath, "run", "--bundle", dir, id}

	runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, runscPath, args...)
	out, runErr := cmd.CombinedOutput()
	_ = exec.Command(runscPath, "delete", "--force", id).Run()

	fmt.Printf("runsc bundle: %s\n", dir)
	if len(out) > 0 {
		fmt.Printf("runsc says: %s\n", strings.TrimSpace(string(out)))
	}

	logData, readErr := os.ReadFile(logPath)
	if readErr != nil {
		fmt.Printf("(no debug log at %s: %v)\n", logPath, readErr)
		return runErr
	}
	fmt.Printf("\n--- last lines of the sentry debug log (%d bytes) ---\n", len(logData))
	lines := strings.Split(strings.TrimRight(string(logData), "\n"), "\n")
	start := 0
	if len(lines) > 40 {
		start = len(lines) - 40
	}
	for _, l := range lines[start:] {
		fmt.Println(" ", l)
	}
	return runErr
}

func writeRootlessWrapper() (string, error) {
	path := filepath.Join(os.TempDir(), "runsc-rootless-wrapper")
	// --network=none is required with --rootless (runsc refuses its
	// default sandbox network there), and happens to be what the policy
	// asks for anyway: v0 always runs with no interfaces at all.
	script := "#!/bin/sh\nexec runsc --rootless --ignore-cgroups --network=none \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		return "", err
	}
	return path, nil
}

func buildProbe() (string, error) {
	out := filepath.Join(os.TempDir(), "doctor-probe")
	cmd := exec.Command("go", "build", "-o", out, "./sandbox/runtime/runsc/probe")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build probe: %w", err)
	}
	return out, nil
}

// dumpTrace prints whatever gVisor logged, which is the only place the
// real boot failure is recorded.
func dumpTrace(traceRoot string) {
	fmt.Printf("\n--- gVisor log ---\n")
	found := false
	_ = filepath.Walk(traceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		found = true
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fmt.Printf("\n[%s] %d bytes\n", path, len(data))
		lines := strings.Split(string(data), "\n")
		start := 0
		if len(lines) > 60 {
			start = len(lines) - 60
		}
		for _, l := range lines[start:] {
			if msg := logMsg(l); msg != "" {
				fmt.Println(" ", msg)
			}
		}
		return nil
	})
	if !found {
		fmt.Printf("(no log files were written to %s)\n", traceRoot)
	}
}

func logMsg(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if !strings.HasPrefix(line, "{") {
		return line
	}
	var e struct {
		Msg string `json:"msg"`
	}
	if json.Unmarshal([]byte(line), &e) == nil && e.Msg != "" {
		return e.Msg
	}
	return line
}
