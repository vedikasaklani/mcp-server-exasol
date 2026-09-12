// Command warden-audit verifies and inspects a hash-chained audit log
// (§7.1).
//
//	warden-audit -verify audit.jsonl     check the chain end to end
//	warden-audit -tail 20 audit.jsonl    show the last N entries
//	warden-audit -findings audit.jsonl   show only behavioural detections
//
// Verification is a separate binary from the daemon on purpose. An audit
// log whose only verifier is the process that wrote it proves very
// little; this one recomputes every hash and checks every checkpoint
// signature from the file alone.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"mcp-warden/sandbox/audit"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden-audit:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-audit", flag.ContinueOnError)
	verify := fs.Bool("verify", false, "verify the chain and report")
	tail := fs.Int("tail", 0, "print the last N entries")
	findingsOnly := fs.Bool("findings", false, "print only behavioural findings")
	asJSON := fs.Bool("json", false, "emit machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: warden-audit [-verify] [-tail N] [-findings] <chain.jsonl>")
	}
	path := fs.Arg(0)

	if !*verify && *tail == 0 && !*findingsOnly {
		*verify = true
	}

	exitBad := false

	if *verify {
		rep, err := audit.Verify(path)
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(rep)
		} else {
			printReport(rep)
		}
		if !rep.Valid {
			exitBad = true
		}
	}

	if *tail > 0 || *findingsOnly {
		n := *tail
		if n == 0 {
			n = 1000
		}
		entries, err := audit.Tail(path, n)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if *findingsOnly && e.Kind != audit.KindFinding {
				continue
			}
			if *asJSON {
				b, _ := json.Marshal(e)
				fmt.Println(string(b))
				continue
			}
			printEntry(e)
		}
	}

	if exitBad {
		os.Exit(2)
	}
	return nil
}

func printReport(r *audit.Report) {
	status := "VALID"
	if !r.Valid {
		status = "INVALID"
	}
	fmt.Printf("chain:        %s\n", status)
	fmt.Printf("entries:      %d (%d executions, %d findings, %d checkpoints)\n",
		r.Entries, r.Executions, r.Findings, r.Checkpoints)
	fmt.Printf("head:         %s\n", r.ChainHead)
	if r.LearningRuns > 0 {
		fmt.Printf("learning:     %d entries recorded UNCONFINED executions\n", r.LearningRuns)
	}
	if r.Gaps > 0 {
		fmt.Printf("gaps:         %d markers covering %d lost entries\n", r.Gaps, r.LostEntries)
	}
	for _, p := range r.Problems {
		fmt.Printf("  ! %s\n", p)
	}
	if r.Valid && r.Gaps == 0 {
		fmt.Println("every entry hashes to its content and links to its predecessor; every checkpoint signature verifies.")
	}
}

func printEntry(e audit.Entry) {
	ts := e.Timestamp.Format("15:04:05.000")
	switch e.Kind {
	case audit.KindExecution:
		x := e.Execution
		line := fmt.Sprintf("%s  exec      %-22s %-8s %5dms", ts, trunc(x.ToolName, 22), x.Status, x.LatencyMS)
		if s := e.Sandbox; s != nil {
			line += fmt.Sprintf("  syscalls=%-6d paths=%-4d read=%-8d netout=%d",
				s.SyscallCount, s.DistinctPaths, s.FileReadBytes, s.NetWriteBytes)
		}
		fmt.Println(line)
	case audit.KindFinding:
		a := e.Analysis
		fmt.Printf("%s  FINDING   [%s/%s] %s: %s\n", ts, a.Severity, a.Confidence, a.Detector, a.Title)
		for _, ev := range a.Evidence {
			fmt.Printf("%s              %s\n", strings.Repeat(" ", 12), ev)
		}
	case audit.KindLifecycle:
		l := e.Lifecycle
		fmt.Printf("%s  lifecycle %s %s %s\n", ts, l.Event, trunc(l.ContainerID, 18), l.Detail)
	case audit.KindCheckpoint:
		fmt.Printf("%s  checkpoint %d entries, head %s\n", ts, e.Checkpoint.Entries, trunc(e.Checkpoint.ChainHead, 26))
	case audit.KindGap:
		fmt.Printf("%s  GAP       %d entries lost: %s\n", ts, e.Gap.Lost, e.Gap.Reason)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
