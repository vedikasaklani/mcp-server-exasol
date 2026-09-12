// Package compile turns a validated CapabilityProfile tool entry into the
// kernel-facing artifacts the runtime layer applies: an OCI seccomp
// document, a Landlock ruleset, and a network configuration.
//
// This package is pure by design: no syscalls, no cgo, no filesystem
// access beyond what's already in memory. Every function here is a plain
// data transformation and is meant to be exhaustively unit-tested without
// root or a target kernel — see the sandbox design note §1. runtime is the
// only package that actually applies what this package produces.
package compile

import (
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/profile"
)

// CompiledPolicy bundles the three kernel-facing artifacts compiled from
// one or more tools' capability declarations. ToolNames records which
// tools contributed to it: a single name for Tool's output, every tool in
// the profile for Session's.
type CompiledPolicy struct {
	ToolNames []string
	Seccomp   *specs.LinuxSeccomp
	Landlock  LandlockRuleset
	Network   NetworkConfig
}

// Options carries runtime-level configuration that isn't part of the
// CapabilityProfile itself but is needed to compile a complete policy.
type Options struct {
	// BrokerSocketPath is where the network egress broker's Unix domain
	// socket will be bind-mounted into the container. See network.go.
	BrokerSocketPath string
}

// Tool compiles a single tool's capability declaration into a
// CompiledPolicy. This is NOT what gets applied to a container in v0 — see
// Session — but it's useful in its own right for per-tool diagnostics
// (e.g. "which tool's declaration would have allowed this syscall") and as
// a building block Session composes. Compilation failure must be treated
// as "this tool cannot be confined" — callers must not fall back to
// running it unconfined (CLAUDE.md: "Sandbox unavailable means calls are
// rejected, never run unconfined").
func Tool(t profile.Tool, opts Options) (*CompiledPolicy, error) {
	seccomp, err := compileSeccomp(t)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	return &CompiledPolicy{
		ToolNames: []string{t.Name},
		Seccomp:   seccomp,
		Landlock:  compileLandlock(t),
		Network:   compileNetwork(t, opts.BrokerSocketPath),
	}, nil
}

// Profile compiles every tool in a CapabilityProfile individually, keyed
// by tool name. Like Tool, this is a diagnostics/documentation view, not
// an enforcement artifact — see Session. A compilation failure on any
// single tool fails the whole call: a profile that can only be partially
// compiled is not a profile this sandbox can safely admit.
func Profile(p *profile.CapabilityProfile, opts Options) (map[string]*CompiledPolicy, error) {
	out := make(map[string]*CompiledPolicy, len(p.Tools))
	for _, t := range p.Tools {
		cp, err := Tool(t, opts)
		if err != nil {
			return nil, fmt.Errorf("compile: profile %s: %w", p.ImageDigest, err)
		}
		out[t.Name] = cp
	}
	return out, nil
}
