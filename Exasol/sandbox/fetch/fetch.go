// Package fetch clones an MCP server from a git repository and detects a
// runnable stdio entrypoint for it — the piece that makes "point
// warden-launch at a GitHub URL" possible: getting the code and figuring
// out how to run it has to happen before anything else in this project's
// sandbox can begin.
//
// Everything in this package runs UNCONFINED on the host. Cloning a
// repository and installing its declared dependencies — npm install, pip
// install, go build — executes that project's own build-time code (npm
// postinstall hooks, setup.py, go generate) with no sandbox around it at
// all. That is a real, acknowledged gap, not an oversight: dependency
// installation is exactly the supply-chain attack surface the rest of
// this project exists to contain, and a source tree pulled from an
// arbitrary URL has not been reviewed by anyone. Every caller must
// surface that loudly before invoking Detect — see cmd/warden-launch,
// which prints an explicit warning before this package does anything.
// Only the server process that Detect's Entrypoint describes ever runs
// inside gVisor.
package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Clone shallow-clones url (optionally at ref) into a fresh temporary
// directory and returns its path. The caller owns cleanup.
func Clone(ctx context.Context, url, ref string) (dir string, err error) {
	dir, err = os.MkdirTemp("", "warden-launch-src-")
	if err != nil {
		return "", fmt.Errorf("fetch: create clone directory: %w", err)
	}
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, url, dir)
	if err := run(ctx, "", "git", args...); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("fetch: git clone %s: %w", url, err)
	}
	return dir, nil
}

// FromNPM installs a published npm package into a fresh temporary
// directory and resolves the stdio command that runs it.
//
// Most of the well-known MCP servers ship as npm packages rather than as
// repositories you build yourself, so this is the shortest honest path to
// "plug in a real server": install it once, on the host, then run only
// the resolved node command inside the sandbox. Installing is subject to
// the same unconfined-execution caveat as everything else in this package
// — npm runs the package's own install scripts.
//
// extraArgs are appended to the server's argv, which is how servers like
// server-filesystem take their allowed directories.
func FromNPM(ctx context.Context, spec string, extraArgs []string) (ep *Entrypoint, dir string, err error) {
	dir, err = os.MkdirTemp("", "warden-npm-")
	if err != nil {
		return nil, "", fmt.Errorf("fetch: create npm dir: %w", err)
	}
	// --prefix keeps the install self-contained in dir; --no-audit and
	// --no-fund cut two registry round trips that only produce console
	// noise here.
	if err := run(ctx, dir, "npm", "install", "--prefix", dir, "--no-audit", "--no-fund", spec); err != nil {
		os.RemoveAll(dir)
		return nil, "", fmt.Errorf("fetch: npm install %s: %w", spec, err)
	}

	pkgName := packageNameOf(spec)
	pkgDir := filepath.Join(dir, "node_modules", filepath.FromSlash(pkgName))
	data, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		os.RemoveAll(dir)
		return nil, "", fmt.Errorf("fetch: read installed package.json for %s: %w", pkgName, err)
	}
	var pkg struct {
		Bin  json.RawMessage `json:"bin"`
		Main string          `json:"main"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		os.RemoveAll(dir)
		return nil, "", fmt.Errorf("fetch: parse installed package.json: %w", err)
	}

	rel := binFromPackageJSON(pkg.Bin, pkgName)
	if rel == "" {
		rel = pkg.Main
	}
	if rel == "" {
		os.RemoveAll(dir)
		return nil, "", fmt.Errorf(`fetch: %s declares neither "bin" nor "main"; it may not be an executable MCP server`, pkgName)
	}

	entry := filepath.Join(pkgDir, filepath.FromSlash(rel))
	if !fileExists(entry) {
		os.RemoveAll(dir)
		return nil, "", fmt.Errorf("fetch: resolved entrypoint %s does not exist", entry)
	}
	cmd := append([]string{"node", entry}, extraArgs...)
	return &Entrypoint{
		Command: cmd,
		Cwd:     pkgDir,
		Kind:    "npm",
		Notes: []string{
			"installed " + spec + " into " + dir,
			"entrypoint resolved from the installed package: " + rel,
		},
	}, dir, nil
}

// binFromPackageJSON resolves the "bin" field, which npm allows to be
// either a bare string or a name->path map.
func binFromPackageJSON(raw json.RawMessage, pkgName string) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if json.Unmarshal(raw, &asString) == nil && asString != "" {
		return asString
	}
	var asMap map[string]string
	if json.Unmarshal(raw, &asMap) != nil || len(asMap) == 0 {
		return ""
	}
	// Prefer the entry named after the package itself; a package with
	// several bins usually names its primary one this way.
	short := pkgName
	if i := strings.LastIndex(short, "/"); i >= 0 {
		short = short[i+1:]
	}
	if v, ok := asMap[short]; ok {
		return v
	}
	keys := make([]string, 0, len(asMap))
	for k := range asMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return asMap[keys[0]]
}

// packageNameOf strips a version or tag suffix from an npm spec, leaving
// the name the package installs under. Scoped names keep their leading
// "@scope/" — only a version separator after it is removed.
func packageNameOf(spec string) string {
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1]
		}
		return spec
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

// Entrypoint is a detected, runnable stdio command for a cloned server.
type Entrypoint struct {
	// Command is the argv to execute. Command[0] and any path arguments
	// are absolute, so the process runs correctly regardless of what
	// working directory the sandbox gives it.
	Command []string
	// Cwd is the working directory the process should start in, for
	// runtimes (notably some Python servers) that read files relative to
	// their own source tree rather than by absolute path.
	Cwd string
	// Kind names what was detected: "node", "python", "go", or "manual".
	Kind string
	// Notes explain what Detect decided and why, for the operator to read
	// before trusting the result.
	Notes []string
}

// Options configures Detect.
type Options struct {
	// Manual, if set, is a pre-built command (already whitespace-split by
	// the caller) that skips detection entirely. Detection heuristics
	// cannot cover "any repo on the internet"; this is the escape hatch
	// for when they guess wrong.
	Manual []string
	// Cwd applies when Manual is set, since there is no detected project
	// root to default to otherwise.
	Cwd string
}

// Detect inspects dir for a recognizable project shape, installs its
// declared dependencies, and returns a runnable command. See the package
// doc: the install step this performs is UNCONFINED.
func Detect(ctx context.Context, dir string, opts Options) (*Entrypoint, error) {
	if len(opts.Manual) > 0 {
		return &Entrypoint{
			Command: opts.Manual,
			Cwd:     opts.Cwd,
			Kind:    "manual",
			Notes:   []string{"using the operator-supplied entrypoint; detection was skipped"},
		}, nil
	}
	switch {
	case fileExists(filepath.Join(dir, "package.json")):
		return detectNode(ctx, dir)
	case fileExists(filepath.Join(dir, "go.mod")):
		return detectGo(ctx, dir)
	case fileExists(filepath.Join(dir, "pyproject.toml")),
		fileExists(filepath.Join(dir, "requirements.txt")),
		fileExists(filepath.Join(dir, "setup.py")):
		return detectPython(ctx, dir)
	default:
		return nil, fmt.Errorf("fetch: no recognizable project in %s (looked for package.json, go.mod, pyproject.toml, requirements.txt, setup.py) — pass -entrypoint", dir)
	}
}

func detectNode(ctx context.Context, dir string) (*Entrypoint, error) {
	var notes []string
	install := []string{"install"}
	if fileExists(filepath.Join(dir, "package-lock.json")) {
		install = []string{"ci"}
	}
	notes = append(notes, "ran: npm "+strings.Join(install, " "))
	if err := run(ctx, dir, "npm", install...); err != nil {
		return nil, fmt.Errorf("fetch: npm %s: %w", strings.Join(install, " "), err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("fetch: read package.json: %w", err)
	}
	var pkg struct {
		Bin  json.RawMessage `json:"bin"`
		Main string          `json:"main"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("fetch: parse package.json: %w", err)
	}

	entry := ""
	if len(pkg.Bin) > 0 {
		var asString string
		var asMap map[string]string
		if json.Unmarshal(pkg.Bin, &asString) == nil && asString != "" {
			entry = asString
		} else if json.Unmarshal(pkg.Bin, &asMap) == nil {
			keys := make([]string, 0, len(asMap))
			for k := range asMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 0 {
				entry = asMap[keys[0]]
			}
		}
		if entry != "" {
			notes = append(notes, `entrypoint from package.json "bin": `+entry)
		}
	}
	if entry == "" {
		for _, cand := range []string{"build/index.js", "dist/index.js", "src/index.js", "index.js", "server.js", "src/server.js"} {
			if fileExists(filepath.Join(dir, cand)) {
				entry = cand
				notes = append(notes, "entrypoint guessed from common filename: "+cand)
				break
			}
		}
	}
	if entry == "" && pkg.Main != "" {
		entry = pkg.Main
		notes = append(notes, `entrypoint from package.json "main": `+entry)
	}
	if entry == "" {
		return nil, fmt.Errorf(`fetch: could not determine a Node entrypoint from package.json ("bin"/"main") or common filenames — pass -entrypoint`)
	}
	return &Entrypoint{Command: []string{"node", filepath.Join(dir, entry)}, Cwd: dir, Kind: "node", Notes: notes}, nil
}

func detectGo(ctx context.Context, dir string) (*Entrypoint, error) {
	var notes []string
	mainPath := "."
	matches, _ := filepath.Glob(filepath.Join(dir, "cmd", "*", "main.go"))
	sort.Strings(matches)
	switch {
	case len(matches) > 0:
		rel, err := filepath.Rel(dir, filepath.Dir(matches[0]))
		if err != nil {
			return nil, fmt.Errorf("fetch: resolve cmd path: %w", err)
		}
		mainPath = "./" + rel
		notes = append(notes, "entrypoint guessed from cmd/ layout: "+mainPath)
	case fileExists(filepath.Join(dir, "main.go")):
		notes = append(notes, "entrypoint is the repository root (main.go)")
	default:
		return nil, fmt.Errorf("fetch: no main.go found at the repository root or under cmd/*/ — pass -entrypoint")
	}

	out := filepath.Join(dir, ".warden-launch-bin")
	notes = append(notes, "ran: go build -o "+out+" "+mainPath)
	if err := run(ctx, dir, "go", "build", "-o", out, mainPath); err != nil {
		return nil, fmt.Errorf("fetch: go build: %w", err)
	}
	return &Entrypoint{Command: []string{out}, Cwd: dir, Kind: "go", Notes: notes}, nil
}

func detectPython(ctx context.Context, dir string) (*Entrypoint, error) {
	var notes []string
	venv := filepath.Join(dir, ".warden-launch-venv")
	if err := run(ctx, dir, "python3", "-m", "venv", venv); err != nil {
		return nil, fmt.Errorf("fetch: python3 -m venv: %w", err)
	}
	notes = append(notes, "created venv: "+venv)
	pip := filepath.Join(venv, "bin", "pip")
	python := filepath.Join(venv, "bin", "python3")

	switch {
	case fileExists(filepath.Join(dir, "pyproject.toml")), fileExists(filepath.Join(dir, "setup.py")):
		notes = append(notes, "ran: pip install -e .")
		if err := run(ctx, dir, pip, "install", "-e", "."); err != nil {
			return nil, fmt.Errorf("fetch: pip install -e .: %w", err)
		}
	case fileExists(filepath.Join(dir, "requirements.txt")):
		notes = append(notes, "ran: pip install -r requirements.txt")
		if err := run(ctx, dir, pip, "install", "-r", "requirements.txt"); err != nil {
			return nil, fmt.Errorf("fetch: pip install -r requirements.txt: %w", err)
		}
	}

	if script := findConsoleScript(dir); script != "" {
		bin := filepath.Join(venv, "bin", script)
		if fileExists(bin) {
			notes = append(notes, `entrypoint from pyproject.toml [project.scripts]: `+script)
			return &Entrypoint{Command: []string{bin}, Cwd: dir, Kind: "python", Notes: notes}, nil
		}
	}
	for _, cand := range []string{"server.py", "main.py", "__main__.py"} {
		if fileExists(filepath.Join(dir, cand)) {
			notes = append(notes, "entrypoint guessed from common filename: "+cand)
			return &Entrypoint{Command: []string{python, filepath.Join(dir, cand)}, Cwd: dir, Kind: "python", Notes: notes}, nil
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "src", "*", "server.py")); len(matches) > 0 {
		sort.Strings(matches)
		notes = append(notes, "entrypoint guessed from src/*/server.py: "+matches[0])
		return &Entrypoint{Command: []string{python, matches[0]}, Cwd: dir, Kind: "python", Notes: notes}, nil
	}
	return nil, fmt.Errorf("fetch: could not determine a Python entrypoint (checked [project.scripts], server.py, main.py, __main__.py, src/*/server.py) — pass -entrypoint")
}

// findConsoleScript does a light-touch scan for the first entry under a
// [project.scripts] table in pyproject.toml. A full TOML parser is not
// worth a dependency for one field; this reads line by line and stops at
// the next "[section]" header, which is enough for the common case and
// wrong only for edge cases -entrypoint exists to override.
func findConsoleScript(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return ""
	}
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inSection = trimmed == "[project.scripts]"
			continue
		}
		if !inSection || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.Index(trimmed, "="); i > 0 {
			if name := strings.Trim(strings.TrimSpace(trimmed[:i]), `"'`); name != "" {
				return name
			}
		}
	}
	return ""
}

func run(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
