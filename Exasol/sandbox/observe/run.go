package observe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// Target describes an arbitrary MCP server to run and observe. Unlike
// sandbox/runtime/runsc's Runtime (which needs a prepared rootfs per
// server image — the right model for an attested, production-confined
// server), Target is built around runsc's own `do` subcommand, which
// mounts the host filesystem read-only with a writable tmpfs overlay.
// That's what makes this package able to run literally any
// already-installed command — a Node script, a Python module, a compiled
// binary — with no per-server image preparation, at the cost of exactly
// the isolation guarantees learning mode already gives up (§6.4: "a
// learning-mode execution is an unconfined execution"). This package is
// the observation half of that mode; sandbox/learning is the confinement
// half.
type Target struct {
	Command []string
	Env     []string
	Cwd     string
	// Requests are sent one at a time over the process's stdin, each
	// followed by a newline; one response line is read back per request
	// and its round-trip latency recorded. A real MCP server speaks
	// newline-delimited JSON-RPC 2.0 over stdio, so a raw
	// `{"jsonrpc":"2.0",...}` line here is exactly what such a server
	// expects — see DefaultMCPInitializeRequest for a ready-made first
	// request.
	Requests [][]byte
	// NetworkMode is passed to runsc's -network flag: "none" (default
	// when empty), "sandbox", or "host". Leave at "none" unless the
	// target genuinely needs to dial out and you specifically want to
	// observe that.
	NetworkMode string
}

// DefaultMCPInitializeRequest returns a minimal, spec-shaped MCP
// `initialize` JSON-RPC request — a reasonable first thing to send any
// unknown MCP stdio server to confirm it's alive and speaking the
// protocol, without needing to already know anything about it.
func DefaultMCPInitializeRequest() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-warden-observe","version":"0.1"}}}`)
}

// RunOptions configures how Run invokes runsc.
type RunOptions struct {
	// RunscPath is the runsc binary to invoke; empty means "runsc" via
	// PATH lookup.
	RunscPath string
	// Timeout bounds the whole run (process start through exit).
	// Defaults to 30s if zero.
	Timeout time.Duration
	// RequestTimeout bounds each individual request/response round trip.
	// Defaults to 10s if zero.
	RequestTimeout time.Duration
	// LogDir, if set, is used (and NOT removed afterward) instead of a
	// temp directory — useful for keeping the raw trace around for
	// manual inspection.
	LogDir string
	// GlobalFlags are extra runsc flags placed before the subcommand,
	// chiefly `--rootless --ignore-cgroups` so profiling can run without
	// root. Learning mode is unconfined either way (§6.4), so this changes
	// nothing about what the target is allowed to do — only about what
	// privileges the host process needs in order to watch it.
	GlobalFlags []string
}

// Run executes target inside a traced, unconfined gVisor sandbox (runsc
// do, with strace+debug logging on), sends every declared request over
// its stdin, and returns a Report built from what gVisor observed. The
// process is never run bare on the host — even in this "run anything"
// mode, gVisor is still the thing actually executing the target.
func Run(ctx context.Context, target Target, opts RunOptions) (*Report, error) {
	if len(target.Command) == 0 {
		return nil, fmt.Errorf("observe: target has no command")
	}
	runscPath := opts.RunscPath
	if runscPath == "" {
		runscPath = "runsc"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout == 0 {
		reqTimeout = 10 * time.Second
	}
	networkMode := target.NetworkMode
	if networkMode == "" {
		networkMode = "none"
	}

	logDir := opts.LogDir
	cleanupLogDir := false
	if logDir == "" {
		var err error
		logDir, err = os.MkdirTemp("", "warden-observe-")
		if err != nil {
			return nil, fmt.Errorf("observe: create log dir: %w", err)
		}
		cleanupLogDir = true
	} else if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("observe: create log dir: %w", err)
	}
	if cleanupLogDir {
		defer os.RemoveAll(logDir)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{}, opts.GlobalFlags...)
	args = append(args,
		"-network="+networkMode,
		"-strace",
		"-debug",
		"-debug-log="+logDir+string(os.PathSeparator),
		"-debug-log-format=json",
		"do",
	)
	if target.Cwd != "" {
		args = append(args, "-cwd", target.Cwd)
	}
	args = append(args, target.Command...)

	cmd := exec.CommandContext(runCtx, runscPath, args...)
	cmd.Env = target.Env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("observe: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("observe: stdout pipe: %w", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("observe: start: %w", err)
	}

	reader := bufio.NewReader(stdout)
	var latencies []time.Duration
	for _, req := range target.Requests {
		t0 := time.Now()
		if _, err := stdin.Write(append(append([]byte{}, req...), '\n')); err != nil {
			break // process likely exited already; stop sending, still build a report from what we have
		}
		// A JSON-RPC notification carries no id and gets no reply, so
		// waiting for one burns the entire request timeout and then reads
		// as a failure — which aborts the rest of the sequence.
		//
		// This is not an edge case for MCP: the handshake *requires*
		// sending notifications/initialized before a server will serve
		// tools, so a profiling run that cannot send a notification
		// either stops at initialize or stalls for the timeout on every
		// single load.
		if isNotification(req) {
			continue
		}
		line, err := readLineWithTimeout(reader, reqTimeout)
		latencies = append(latencies, time.Since(t0))
		if err != nil {
			break
		}
		_ = line // response content isn't validated here; latency and trace are the signal this package collects
	}
	_ = stdin.Close()

	waitErr := cmd.Wait()
	duration := time.Since(started)

	events, parseErr := parseLogDir(logDir)

	report := BuildReport(target, events)
	report.StartedAt = started
	report.Duration = duration
	report.RequestLatencies = latencies
	if waitErr != nil {
		report.ExitErr = waitErr.Error()
		if stderrBuf.Len() > 0 {
			report.ExitErr += ": " + stderrBuf.String()
		}
	}
	if parseErr != nil && report.RawEventCount == 0 {
		return report, fmt.Errorf("observe: parse trace log: %w", parseErr)
	}
	return report, nil
}

// isNotification reports whether payload is a JSON-RPC notification: a
// message with a method and no id. The absence of the field is what
// defines it, so a payload that is not JSON at all is treated as a
// request — the harness should wait for a reply it might get rather than
// skip one it should have.
func isNotification(payload []byte) bool {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return false
	}
	if _, hasMethod := msg["method"]; !hasMethod {
		return false
	}
	id, hasID := msg["id"]
	if !hasID {
		return true
	}
	return string(id) == "null"
}

func readLineWithTimeout(r *bufio.Reader, timeout time.Duration) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		return res.line, res.err
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out after %s", timeout)
	}
}

// parseLogDir reads every log file runsc wrote into dir and returns all
// parsed events, sorted by timestamp. runsc writes separate files per
// component (boot, gofer, the `do` wrapper itself); strace output for the
// workload lives in the boot log, but this reads all of them rather than
// hardcoding that filename, since it's an implementation detail of a
// specific runsc version, not a documented contract.
func parseLogDir(dir string) ([]SyscallEvent, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read log dir: %w", err)
	}
	var all []SyscallEvent
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		events, _ := ParseStream(f)
		f.Close()
		all = append(all, events...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, nil
}
