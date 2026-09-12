package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// bootFailureMarkers are the substrings worth pulling out of a gVisor
// debug log when a sandbox died during boot. The log is enormous and
// almost entirely uninteresting; these are the lines that say why.
var bootFailureMarkers = []string{
	"Fatal error", "FATAL", "panic", "Error creating", "failed to",
	"cannot ", "no such file", "permission denied", "too many open files",
	"invalid argument", "Failed to",
}

// diagnoseBootFailure prints what gVisor itself said when a container
// would not start.
//
// runsc's frontend reports "cannot read client sync file: EOF", which
// only means the sandbox process exited before it finished booting. The
// actual cause — a mount it could not open, a file descriptor limit, an
// unsupported platform — is written to the debug log by the sentry on its
// way down, and is otherwise lost.
func diagnoseBootFailure(traceRoot, bundleRoot string, mountCount int) {
	fmt.Println()
	step("the sandbox did not boot — reading gVisor's own log")

	lines := collectBootErrors(traceRoot)
	if len(lines) == 0 {
		detail("no diagnostic lines found in %s", traceRoot)
	}
	for _, l := range lines {
		fmt.Printf("  %s%s%s\n", colCritical, trunc(l, 160), ansiReset)
	}

	fmt.Println()
	detail("mounts in this container: %d", mountCount)
	if cur, max, err := nofileLimit(); err == nil {
		detail("open-file limit: %d soft / %d hard", cur, max)
		if uint64(mountCount)*3 > cur {
			warn("that mount count is large relative to the open-file limit — each bind mount costs the gofer descriptors. Try `set rollup 5` and load again, which collapses the profile's paths into far fewer mounts (it widens the grants, and `profile` will show you by how much).")
		}
	}
	detail("bundle kept for inspection: %s", bundleRoot)
	detail("gVisor log kept for inspection: %s", traceRoot)
	detail("the OCI spec (mounts, seccomp, cgroups) is at %s/<container-id>/config.json", bundleRoot)
}

// collectBootErrors walks a trace directory and returns the interesting
// lines, newest last, bounded so a multi-gigabyte log cannot flood the
// terminal.
func collectBootErrors(traceRoot string) []string {
	var out []string
	seen := map[string]bool{}

	_ = filepath.WalkDir(traceRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			msg := logMessage(line)
			if !interesting(msg) {
				continue
			}
			if seen[msg] {
				continue
			}
			seen[msg] = true
			out = append(out, msg)
			if len(out) >= 20 {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return out
}

// logMessage pulls the human-readable part out of a gVisor JSON log line,
// falling back to the raw line for any other format.
func logMessage(line string) string {
	if !strings.HasPrefix(strings.TrimSpace(line), "{") {
		return line
	}
	var entry struct {
		Msg     string `json:"msg"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return line
	}
	if entry.Msg != "" {
		return entry.Msg
	}
	if entry.Message != "" {
		return entry.Message
	}
	return line
}

func interesting(msg string) bool {
	// Strace lines are the bulk of the log and are never the reason a
	// sandbox failed to boot.
	if strings.Contains(msg, "X-") || strings.Contains(msg, "E-") {
		return false
	}
	for _, m := range bootFailureMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func nofileLimit() (cur, max uint64, err error) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, 0, err
	}
	return rl.Cur, rl.Max, nil
}

// raiseNofile lifts the soft open-file limit to the hard limit.
//
// Every bind mount in a confined container costs the gofer descriptors,
// and a real server's profile grants hundreds of paths. The default soft
// limit of 1024 is low enough that a sandbox can die during boot with
// nothing but an EOF to show for it — which is a failure mode worth
// removing rather than diagnosing twice.
func raiseNofile() (uint64, bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, false
	}
	if rl.Cur >= rl.Max {
		return rl.Cur, false
	}
	raised := syscall.Rlimit{Cur: rl.Max, Max: rl.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &raised); err != nil {
		return rl.Cur, false
	}
	return rl.Max, true
}
