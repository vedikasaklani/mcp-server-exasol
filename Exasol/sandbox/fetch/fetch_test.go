package fetch

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not on PATH; skipping", name)
	}
}

func TestDetect_ManualBypassesDetection(t *testing.T) {
	dir := t.TempDir()
	ep, err := Detect(context.Background(), dir, Options{Manual: []string{"node", "server.js"}, Cwd: "/somewhere"})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ep.Kind != "manual" || len(ep.Command) != 2 || ep.Command[0] != "node" {
		t.Fatalf("unexpected entrypoint: %+v", ep)
	}
	if ep.Cwd != "/somewhere" {
		t.Fatalf("cwd not preserved: %+v", ep)
	}
}

func TestDetect_UnrecognizedProjectFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Detect(context.Background(), dir, Options{}); err == nil {
		t.Fatalf("expected an error for an empty directory")
	}
}

func TestDetectNode_BinString(t *testing.T) {
	requireTool(t, "npm")
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"x","version":"1.0.0","bin":"./run.js"}`)
	mustWrite(t, filepath.Join(dir, "run.js"), "console.log('hi')")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ep, err := Detect(ctx, dir, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ep.Kind != "node" {
		t.Fatalf("want kind node, got %s", ep.Kind)
	}
	want := filepath.Join(dir, "run.js")
	if len(ep.Command) != 2 || ep.Command[0] != "node" || ep.Command[1] != want {
		t.Fatalf("unexpected command: %+v (want [node %s])", ep.Command, want)
	}
}

func TestDetectNode_FallsBackToCommonFilename(t *testing.T) {
	requireTool(t, "npm")
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"x","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(dir, "index.js"), "console.log('hi')")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ep, err := Detect(ctx, dir, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := filepath.Join(dir, "index.js")
	if ep.Command[1] != want {
		t.Fatalf("want entrypoint %s, got %+v", want, ep.Command)
	}
}

func TestDetectGo_CmdLayout(t *testing.T) {
	requireTool(t, "go")
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	mustWrite(t, filepath.Join(dir, "cmd", "srv", "main.go"), "package main\n\nfunc main() {}\n")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ep, err := Detect(ctx, dir, Options{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if ep.Kind != "go" {
		t.Fatalf("want kind go, got %s", ep.Kind)
	}
	if _, err := os.Stat(ep.Command[0]); err != nil {
		t.Fatalf("built binary missing: %v", err)
	}
}

func TestFindConsoleScript(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pyproject.toml"), `
[project]
name = "x"

[project.scripts]
my-server = "x.server:main"

[build-system]
requires = ["setuptools"]
`)
	if got := findConsoleScript(dir); got != "my-server" {
		t.Fatalf("want my-server, got %q", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
