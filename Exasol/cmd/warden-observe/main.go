// Command warden-observe runs an arbitrary MCP server (or any command,
// really) inside a traced, unconfined gVisor sandbox, and reports what it
// observed: every syscall made, every file touched, request/response
// latency, and findings from a pluggable set of heuristics — see
// sandbox/observe.
//
// Usage:
//
//	warden-observe [flags] -- <command> [args...]
//
// Example, against any already-installed stdio MCP server:
//
//	warden-observe -- node /path/to/server.js
//	warden-observe -- python3 -m my_mcp_server
//	warden-observe -- /usr/local/bin/my-compiled-server
//
// By default it sends one MCP `initialize` request and reports on
// whatever the server did in response to that plus its own startup. Pass
// -requests to exercise it with a custom sequence instead.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"mcp-warden/sandbox/observe"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden-observe:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-observe", flag.ContinueOnError)
	network := fs.String("network", "none", "runsc network mode: none, sandbox, or host")
	timeout := fs.Duration("timeout", 30*time.Second, "overall run timeout")
	reqTimeout := fs.Duration("request-timeout", 10*time.Second, "per-request/response timeout")
	requestsFile := fs.String("requests", "", "path to a file of newline-delimited request payloads to send over stdin (default: one MCP initialize request)")
	noRequests := fs.Bool("no-requests", false, "send nothing; just observe startup/exit")
	keepLog := fs.String("keep-log", "", "directory to keep the raw gVisor trace log in (default: a temp dir, deleted after the run)")
	asJSON := fs.Bool("json", false, "print the report and findings as JSON instead of a human-readable summary")
	topN := fs.Int("top", 15, "number of syscalls to show in the by-time summary")
	emitProfile := fs.String("emit-profile", "", "write a candidate CapabilityProfile JSON to this path (it will be UNAPPROVED and must be reviewed before use)")
	approvedBy := fs.String("approved-by", "", "approver identity to stamp into the emitted profile (empty keeps the profile UNAPPROVED; for automation recording only, not human review)")
	toolName := fs.String("tool-name", "observed", "tool name to use in the emitted profile")
	rollupDepth := fs.Int("rollup-depth", 0, "collapse observed paths to N leading directory components in the emitted profile (0 = exact paths)")
	var writePaths stringList
	fs.Var(&writePaths, "write-path", "path prefix the server may write to in the emitted profile (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("no command given; usage: warden-observe [flags] -- <command> [args...]")
	}

	var requests [][]byte
	switch {
	case *noRequests:
		// leave empty
	case *requestsFile != "":
		f, err := os.Open(*requestsFile)
		if err != nil {
			return fmt.Errorf("open -requests file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			requests = append(requests, append([]byte{}, line...))
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("read -requests file: %w", err)
		}
	default:
		requests = [][]byte{observe.DefaultMCPInitializeRequest()}
	}

	target := observe.Target{
		Command:     command,
		Requests:    requests,
		NetworkMode: *network,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	report, err := observe.Run(ctx, target, observe.RunOptions{
		Timeout:        *timeout,
		RequestTimeout: *reqTimeout,
		LogDir:         *keepLog,
		RunscPath:      os.Getenv("WARDEN_RUNSC_BIN"),
		GlobalFlags:    runscGlobalFlags(),
	})
	if err != nil && report == nil {
		return err
	}

	findings := observe.Evaluate(report, observe.DefaultHeuristics())

	if *asJSON {
		if err := printJSON(report, findings); err != nil {
			return err
		}
	} else {
		printSummary(report, findings, *topN)
		if *keepLog != "" {
			fmt.Printf("\nraw trace log kept at: %s\n", *keepLog)
		}
	}

	if *emitProfile != "" {
		return writeCandidateProfile(report, *approvedBy, *emitProfile, observe.ProfileOptions{
			ToolName:    *toolName,
			RollupDepth: *rollupDepth,
			WritePaths:  writePaths,
		})
	}
	return nil
}

// stringList collects a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// runscGlobalFlags returns the runsc flags this host needs. As root, none:
// gVisor can configure cgroups. Unprivileged, runsc fails at
// /sys/fs/cgroup/cgroup.subtree_control and refuses its default network
// mode, so both must be turned off — the same shape warden-console uses.
func runscGlobalFlags() []string {
	if os.Geteuid() == 0 {
		return nil
	}
	return []string{"--rootless", "--ignore-cgroups", "--network=none"}
}

func writeCandidateProfile(report *observe.Report, approvedBy, path string, opts observe.ProfileOptions) error {
	cand, err := observe.GenerateProfile(report, opts)
	if err != nil {
		return fmt.Errorf("generate profile: %w", err)
	}
	if approvedBy != "" {
		cand.Profile.ApprovedBy = approvedBy
	}
	data, err := json.MarshalIndent(cand.Profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	tool := cand.Profile.Tools[0]
	fmt.Printf("\ncandidate profile written to %s\n", path)
	fmt.Printf("  syscalls granted: %d\n", len(tool.Syscalls))
	fmt.Printf("  read paths:       %d\n", len(tool.Filesystem.Read))
	fmt.Printf("  write paths:      %d\n", len(tool.Filesystem.Write))
	fmt.Printf("  skipped (virtual/sandbox-provided): %d\n", len(cand.SkippedVirtual))
	fmt.Printf("  skipped (no longer on disk):        %d\n", len(cand.SkippedMissing))
	fmt.Printf("  dropped (traversal-only parents):   %d\n", len(cand.DroppedAncestors))

	if len(cand.BroadGrants) > 0 {
		fmt.Printf("\n  *** DO NOT APPROVE AS-IS ***\n")
		fmt.Printf("  This profile grants whole system trees: %s\n", strings.Join(cand.BroadGrants, ", "))
		fmt.Printf("  Mounting these exposes far more than this server needs. Narrow them\n")
		fmt.Printf("  to the specific subdirectories the server actually uses before approving.\n")
	}

	if len(cand.Widenings) > 0 {
		fmt.Printf("\n  REVIEW REQUIRED — rollup granted broader access than was observed:\n")
		for _, w := range cand.Widenings {
			fmt.Printf("    %s  (covers %d observed paths, e.g. %s)\n", w.Granted, w.CoveredN, strings.Join(w.Examples, ", "))
		}
	}

	if approvedBy != "" {
		fmt.Printf("\n  approved_by: %s\n", cand.Profile.ApprovedBy)
		fmt.Printf("  This is an AUTOMATION placeholder approval (see CONTEXT.md). It records who ran\n")
		fmt.Printf("  the machine flow — it is not evidence of human review.\n")
	} else {
		fmt.Printf("\n  This profile is UNAPPROVED and will fail validation until an operator\n")
		fmt.Printf("  reviews it and sets \"approved_by\". That gate is deliberate (§3.2 step 5):\n")
		fmt.Printf("  a server that misbehaved during profiling would otherwise have that\n")
		fmt.Printf("  behavior baked into its own allowlist.\n")
	}
	return nil
}

func printJSON(report *observe.Report, findings []observe.Finding) error {
	out := struct {
		Report   *observe.Report   `json:"report"`
		Findings []observe.Finding `json:"findings"`
	}{report, findings}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func printSummary(r *observe.Report, findings []observe.Finding, topN int) {
	fmt.Printf("target:      %v\n", r.Target.Command)
	fmt.Printf("duration:    %v\n", r.Duration)
	if r.ExitErr != "" {
		fmt.Printf("exit:        %s\n", r.ExitErr)
	} else {
		fmt.Printf("exit:        clean\n")
	}
	fmt.Printf("raw events:  %d\n", r.RawEventCount)
	fmt.Printf("syscalls:    %d unique\n", len(r.Syscalls))
	fmt.Printf("paths:       %d unique\n", len(r.Paths))

	if len(r.RequestLatencies) > 0 {
		fmt.Printf("\nrequest latencies (%d):\n", len(r.RequestLatencies))
		min, max, sum := r.RequestLatencies[0], r.RequestLatencies[0], time.Duration(0)
		for i, d := range r.RequestLatencies {
			fmt.Printf("  #%d: %v\n", i+1, d)
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
			sum += d
		}
		fmt.Printf("  min=%v max=%v avg=%v\n", min, max, sum/time.Duration(len(r.RequestLatencies)))
	}

	fmt.Printf("\ntop syscalls by total time:\n")
	for _, st := range r.TopSyscallsByTime(topN) {
		fmt.Printf("  %-20s count=%-6d errors=%-4d total=%-12v max=%v\n", st.Syscall, st.Count, st.ErrorCount, st.TotalTime, st.MaxTime)
	}

	if len(r.Paths) > 0 {
		paths := make([]string, 0, len(r.Paths))
		for p := range r.Paths {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		fmt.Printf("\npaths touched:\n")
		for _, p := range paths {
			pa := r.Paths[p]
			fmt.Printf("  [%s] %-60s count=%d\n", pa.Kind, p, pa.Count)
		}
	}

	if len(findings) == 0 {
		fmt.Printf("\nheuristic findings: none\n")
		return
	}
	fmt.Printf("\nheuristic findings (%d):\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [%s] %s: %s\n", f.Severity, f.Heuristic, f.Message)
	}
}
