// Command warden-console is an interactive terminal for running untrusted
// MCP servers under kernel-enforced confinement.
//
// You start it once and then type commands at it:
//
//	$ sudo warden-console
//	warden> load npm:@modelcontextprotocol/server-everything
//	warden> tools
//	warden> call echo {"message":"hi"}
//	warden> scan
//	warden> watch
//	warden> stop
//	warden> quit
//
// Everything the non-interactive tools do — clone or install a server,
// profile it in learning mode, compile a seccomp/mount policy from that
// profile, run it in gVisor, analyse the syscall stream, and write a
// hash-chained audit log — happens inside this one process, driven by
// what you type rather than by flags fixed at startup.
//
// It needs root, because gVisor needs root on most hosts to set up
// cgroups and namespaces. That is also why fetching and building a server
// runs as root here: a real deployment would separate those privileges,
// and this console does not. `help` says so, and so does `load`.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mcp-warden/sandbox/registry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "warden-console:", err)
		os.Exit(1)
	}
}

type console struct {
	repoRoot string
	probeBin string
	sess     *session

	lines chan string
	opts  loadOptions

	// storage feeds the Exasol trust/reputation platform (discovery,
	// reputation, audit trail). Disabled with `set storage off`; a nil
	// baseURL makes every call on it a no-op, so nothing downstream needs
	// to check whether it's configured.
	storage   *registry.Client
	exasolAPI string
	// sastWG tracks in-flight async SAST scans (see session.go's load),
	// so quitting the console doesn't silently kill one mid-scan — its
	// result would otherwise never reach Exasol at all.
	sastWG sync.WaitGroup
}

const defaultExasolAPI = "http://localhost:8000"

func run() error {
	c := &console{opts: defaultLoadOptions(), lines: make(chan string, 8), exasolAPI: defaultExasolAPI}
	c.storage = registry.New(c.exasolAPI)

	root, err := findModuleRoot()
	if err != nil {
		return err
	}
	c.repoRoot = root

	banner()
	if rootless() {
		warn("running unprivileged: seccomp and mount confinement are fully enforced (the canary proves it per container), but cgroup resource limits (§6.1.5) are OFF — a loaded server can exhaust host CPU or memory. Run under sudo for the fully confined configuration.")
	}
	if limit, raised := raiseNofile(); raised {
		detail("raised the open-file limit to %d (every bind mount in a confined container costs the gofer descriptors)", limit)
	}

	step("building the sandbox probe binary")
	probe, err := c.buildProbe()
	if err != nil {
		return err
	}
	c.probeBin = probe
	ok(" probe ready")
	fmt.Println()
	printHelp()

	// One reader for stdin, shared by the prompt and by `watch`, so the
	// two never race for the same line.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()

	// Ctrl-C cancels whatever command is running rather than killing the
	// console: a tool that destroys a container fleet on a stray keystroke
	// is a tool people stop trusting with long sessions.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	for {
		fmt.Print(prompt(c.sess))
		line, open := <-c.lines
		if !open {
			fmt.Println()
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cmdCtx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			select {
			case <-sigCh:
				fmt.Println()
				warn("interrupted")
				cancel()
			case <-done:
			}
		}()

		quit := c.dispatch(cmdCtx, line)
		close(done)
		cancel()

		if quit {
			break
		}
	}

	if c.sess != nil {
		step("shutting down: draining requests, destroying containers")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c.sess.close(ctx)
		cancel()
		ok(" all containers destroyed; no sandbox state persists")
	}
	c.waitForSAST()
	return nil
}

// waitForSAST blocks briefly for any SAST scan still running in the
// background, so its result reaches Exasol instead of being silently
// dropped by process exit. Bounded: a scan that's still running after 20s
// (an unusually large source tree) is left to finish or die with the
// process rather than holding the console open indefinitely.
func (c *console) waitForSAST() {
	done := make(chan struct{})
	go func() {
		c.sastWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		detail("a SAST scan is still running past 20s — its result may not be recorded")
	}
}

// dispatch runs one typed command. It returns true when the console
// should exit.
func (c *console) dispatch(ctx context.Context, line string) bool {
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "help", "?":
		printHelp()

	case "servers":
		printServers()

	case "load":
		c.cmdLoad(ctx, args, line)

	case "set":
		c.cmdSet(args)

	case "tools":
		c.cmdTools(ctx)

	case "call":
		c.cmdCall(ctx, args, line)

	case "raw":
		c.cmdRaw(ctx, line)

	case "scan":
		c.cmdScan()

	case "status":
		c.cmdStatus()

	case "watch":
		c.cmdWatch(ctx, args)

	case "findings":
		c.cmdFindings()

	case "containers":
		c.cmdContainers()

	case "profile":
		c.cmdProfile()

	case "audit":
		c.cmdAudit(args)

	case "rescan":
		c.cmdRescan()

	case "reputation", "score":
		c.cmdReputation(ctx)

	case "stop":
		c.cmdStop()

	case "quit", "exit":
		return true

	default:
		fail("unknown command %q — type `help`", cmd)
	}
	return false
}

func (c *console) cmdLoad(ctx context.Context, args []string, line string) {
	if len(args) == 0 {
		fail("usage: load <source> [server args...]   (try `servers` for ready-made options)")
		return
	}
	if c.sess != nil {
		fail("a server is already loaded — `stop` it first")
		return
	}

	spec := args[0]
	if alias, extra, ok := lookupAlias(spec); ok {
		detail("%s -> %s", spec, alias)
		spec = alias
		args = append(append([]string{spec}, extra...), args[1:]...)
	}

	start := time.Now()
	sess, err := c.load(ctx, spec, args[1:], c.opts)
	if err != nil {
		fail("load: %v", err)
		return
	}
	c.sess = sess
	ok(" %s is confined and serving (%v)", sess.kind, time.Since(start).Round(time.Millisecond))
	fmt.Println()
	c.cmdStatus()
}

func (c *console) cmdSet(args []string) {
	if len(args) == 0 {
		fmt.Printf("  pool          %d\n", c.opts.poolSize)
		fmt.Printf("  network       %s\n", c.opts.networkMode)
		fmt.Printf("  analyze       %s\n", c.opts.analyze)
		fmt.Printf("  rollup        %d %s\n", c.opts.rollup, rollupNote(c.opts.rollup))
		fmt.Printf("  learn-timeout %s\n", c.opts.learnTimeout)
		fmt.Printf("  timeout       %s\n", c.opts.reqTimeout)
		fmt.Printf("  write-path    %v\n", c.opts.writePaths)
		fmt.Printf("  sast          %v\n", c.opts.sast)
		fmt.Printf("  storage       %v (%s)\n", c.storage.Enabled(), c.exasolAPI)
		detail("settings apply to the next `load`")
		return
	}
	if len(args) < 2 {
		fail("usage: set <key> <value>")
		return
	}
	key, value := args[0], strings.Join(args[1:], " ")
	switch key {
	case "pool":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			fail("pool must be a positive integer")
			return
		}
		c.opts.poolSize = n
	case "network":
		if value != "none" && value != "sandbox" && value != "host" {
			fail("network must be none, sandbox or host")
			return
		}
		c.opts.networkMode = value
	case "analyze":
		if value != "off" && value != "detect" && value != "full" {
			fail("analyze must be off, detect or full")
			return
		}
		c.opts.analyze = value
	case "rollup":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			fail("rollup must be 0 (exact paths) or a positive directory depth")
			return
		}
		c.opts.rollup = n
		if n > 0 {
			warn("rollup grants whole directories instead of individual files: fewer mounts, broader access. `profile` shows what was granted.")
		}
	case "learn-timeout", "timeout":
		d, err := time.ParseDuration(value)
		if err != nil {
			fail("not a duration: %v", err)
			return
		}
		if key == "timeout" {
			c.opts.reqTimeout = d
		} else {
			c.opts.learnTimeout = d
		}
	case "write-path":
		c.opts.writePaths = append(c.opts.writePaths, value)
	case "sast":
		c.opts.sast = value == "on" || value == "true"
	case "storage":
		if value == "on" || value == "true" {
			c.storage = registry.New(c.exasolAPI)
		} else {
			c.storage = registry.New("")
		}
	case "exasol-api":
		c.exasolAPI = value
		c.storage = registry.New(value)
	default:
		fail("unknown setting %q", key)
		return
	}
	ok(" %s = %s (applies to the next load)", key, value)
}

func (c *console) cmdStop() {
	if c.sess == nil {
		fail("nothing loaded")
		return
	}
	step("destroying containers")
	c.waitForSAST()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c.sess.mon.Evaluate()
	score := c.sess.mon.Score()
	snap := c.sess.mon.Aggregate()
	findings := c.sess.mon.Findings()
	narrative := c.sess.mon.Narrative()
	auditPath := c.sess.auditPath

	c.sess.close(ctx)
	c.sess = nil

	fmt.Println()
	printFinalReport(score, snap, findings, narrative, auditPath)
	ok(" containers destroyed; tmpfs discarded")
}

// findModuleRoot locates the mcp-warden checkout, which the console needs
// in order to build the probe binary every confined container mounts.
func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			if strings.HasPrefix(string(data), "module mcp-warden") {
				return dir, nil
			}
			return "", fmt.Errorf("found go.mod at %s but it is not mcp-warden's — run warden-console from inside the mcp-warden repository", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no mcp-warden go.mod found above the working directory — run warden-console from inside the repository (it builds the sandbox probe binary from source)")
		}
		dir = parent
	}
}

// buildProbe compiles the static probe every container mounts read-only
// for its confinement self-test. Cached across runs; `go build` is
// incremental, so a rebuild is nearly free once warm.
func (c *console) buildProbe() (string, error) {
	binDir := filepath.Join(os.TempDir(), "mcp-warden-console-bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(binDir, "probe")
	cmd := exec.Command("go", "build", "-o", out, "./sandbox/runtime/runsc/probe")
	cmd.Dir = c.repoRoot
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build probe binary: %w (is go on PATH? under sudo, try: sudo -E env PATH=$PATH warden-console)", err)
	}
	return out, nil
}
