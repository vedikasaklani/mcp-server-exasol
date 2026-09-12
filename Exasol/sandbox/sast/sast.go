// Package sast shells out to mcp-server-exasol's sast_cli.py — Semgrep SAST
// plus mechanical tool-declaration extraction, run against exactly the
// source tree sandbox/fetch already pulled down for learning mode. This is
// deliberately not a Go reimplementation of Semgrep's rule config: the
// Python side owns the ruleset and severity mapping, and this package's
// only job is to run it and parse its JSON.
//
// Like sandbox/fetch, this runs UNCONFINED — it invokes an external tool
// against a source tree that hasn't been reviewed. It doesn't execute the
// server itself, only Semgrep's own static analysis of it, which is the
// same trust boundary static_analysis.py already documents on its own.
package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// Finding mirrors what sast_cli.py emits per finding.
type Finding struct {
	Analyzer string `json:"analyzer"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// ToolDeclaration mirrors static_analysis.py's extract_tool_declarations
// output — the "declared" half of tool discovery.
type ToolDeclaration struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	ParameterSchema any    `json:"parameter_schema"`
}

// Report is sast_cli.py's whole stdout payload.
type Report struct {
	ToolDeclarations []ToolDeclaration `json:"tool_declarations"`
	Findings         []Finding         `json:"findings"`
	Error            string            `json:"error"`
}

// Options configures Run.
type Options struct {
	// PythonRepo is the mcp-server-exasol checkout containing sast_cli.py.
	// Defaults to "mcp-server-exasol" next to the warden module root.
	PythonRepo string
	// Python is the interpreter to invoke. Defaults to "python3" on PATH.
	Python string
	// Timeout bounds the whole scan. Defaults to 60s.
	Timeout time.Duration
}

// Run scans srcDir and returns whatever sast_cli.py produced. A non-nil
// error means the CLI itself couldn't be run at all (python3 missing, the
// mcp-server-exasol checkout missing, a timeout) — a scan-step failure
// inside a healthy CLI invocation instead shows up in Report.Error, with
// whatever findings the other steps still produced.
func Run(ctx context.Context, srcDir string, opts Options) (*Report, error) {
	python := opts.Python
	if python == "" {
		python = "python3"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	repo := opts.PythonRepo
	if repo == "" {
		repo = "mcp-server-exasol"
	}
	repo, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("sast: resolve python repo path: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, python, "-m", "server_management.services.sast_cli", srcDir)
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sast: sast_cli.py: %w: %s", err, stderr.String())
	}

	var report Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("sast: parse sast_cli.py output: %w", err)
	}
	return &report, nil
}
