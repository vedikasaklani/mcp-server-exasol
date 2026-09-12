// Package profile parses and validates CapabilityProfile documents (§8.2).
//
// This package has no knowledge of the kernel, runsc, or seccomp/Landlock —
// it only turns bytes into validated Go structs. That boundary is
// deliberate: profile/compile stay testable and reviewable without root or
// a target kernel, so mistakes here are caught by go test, not by running
// an exploit against a live container. See docs/ARCHITECTURE.md §6 and the
// sandbox design note for the full rationale.
package profile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SupportedProfileVersions lists the profile_version values this build
// knows how to compile. Compiling an unrecognized version is a validation
// error, not a best-effort attempt — an old or unknown profile shape is
// exactly the kind of ambiguity that must fail closed.
var SupportedProfileVersions = map[string]bool{
	"1.0": true,
}

// Effect enumerates the tool effects declared in §5.3's taint model. The
// sandbox module doesn't act on these (that's IBAC / v1), but it parses and
// validates them now so the CapabilityProfile schema doesn't have to change
// shape when IBAC lands.
type Effect string

const (
	EffectRead  Effect = "read"
	EffectWrite Effect = "write"
	EffectExec  Effect = "exec"
)

var validEffects = map[Effect]bool{
	EffectRead:  true,
	EffectWrite: true,
	EffectExec:  true,
}

// ResourceExtractor names the argument and type used to extract the target
// resource for a tool call, per §5.1: "extracted from arguments by a typed
// extractor declared in the capability profile — never by a model."
type ResourceExtractor struct {
	Arg  string `json:"arg"`
	Type string `json:"type"`
}

// FilesystemAccess separates read and write path sets, per §6.1.3: "Read
// and write sets are separate."
type FilesystemAccess struct {
	Read  []string `json:"read"`
	Write []string `json:"write"`
}

// NetworkDestination is one declared, explicit egress allowlist entry
// (§6.1.4). There is no wildcard form — every destination is host, port,
// and protocol, named exactly.
type NetworkDestination struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// Tool is one entry in a CapabilityProfile's tool list — the compiled
// capability allowlist for a single MCP tool.
type Tool struct {
	Name              string               `json:"name"`
	ResourceExtractor ResourceExtractor    `json:"resource_extractor"`
	Effects           []Effect             `json:"effects"`
	Syscalls          []string             `json:"syscalls"`
	Filesystem        FilesystemAccess     `json:"filesystem"`
	Network           []NetworkDestination `json:"network"`
	MaxDurationMS     int                  `json:"max_duration_ms"`
}

// EntrypointAttestation pins the identity of the executable a profile was
// approved for, and of the ELF interpreter that maps it.
//
// The interpreter is pinned separately because it is unobservable by
// every other mechanism here: the sandbox's own kernel maps it inside
// execve, so it appears in no syscall trace and in no capability profile
// generated from one. An attacker who can replace ld.so controls every
// dynamically linked process on the image while leaving the traced
// behaviour of each one unchanged.
//
// Optional. A profile without it is still valid — digest pinning is a
// strengthening of §3.3's attestation story, not a precondition for
// confinement — but a profile with it lets the runtime refuse to start
// code that is not the code a human reviewed.
type EntrypointAttestation struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	Interpreter       string `json:"interpreter,omitempty"`
	InterpreterSHA256 string `json:"interpreter_sha256,omitempty"`
}

// CapabilityProfile is the parsed form of the schema in §8.2.
type CapabilityProfile struct {
	ProfileVersion string                 `json:"profile_version"`
	ImageDigest    string                 `json:"image_digest"`
	GeneratedBy    string                 `json:"generated_by"`
	ApprovedBy     string                 `json:"approved_by"`
	ParallelSafe   bool                   `json:"parallel_safe"`
	Entrypoint     *EntrypointAttestation `json:"entrypoint,omitempty"`
	Tools          []Tool                 `json:"tools"`
}

// ToolByName returns the tool entry for name, if any. Callers must treat a
// missing tool as "no allowlist exists for this call" and deny — never as
// "no restrictions apply."
func (p *CapabilityProfile) ToolByName(name string) (Tool, bool) {
	for _, t := range p.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Parse decodes a CapabilityProfile from r and validates it. Unknown JSON
// fields are rejected: a profile with a field this build doesn't recognize
// is more likely a schema-version mismatch than a typo, and silently
// ignoring it would silently drop whatever constraint that field encoded.
func Parse(r io.Reader) (*CapabilityProfile, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var p CapabilityProfile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("profile: decode: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("profile: trailing data after JSON document")
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("profile: invalid: %w", err)
	}
	return &p, nil
}

// Load reads and parses a CapabilityProfile from a file path. v0 policy is
// a flat file (CLAUDE.md: "no OpenFGA ... flat-file deterministic policy"),
// so this is the only loader v0 needs; attestation-backed loading is v1.
func Load(path string) (*CapabilityProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("profile: open %s: %w", path, err)
	}
	defer f.Close()

	p, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("profile: %s: %w", path, err)
	}
	return p, nil
}

// Validate checks structural and policy invariants. It is deliberately
// strict: every rejection here is a profile that would otherwise compile
// into an ambiguous or overly permissive kernel policy.
func (p *CapabilityProfile) Validate() error {
	var errs []string

	if !SupportedProfileVersions[p.ProfileVersion] {
		errs = append(errs, fmt.Sprintf("unsupported profile_version %q", p.ProfileVersion))
	}
	if !strings.HasPrefix(p.ImageDigest, "sha256:") || len(p.ImageDigest) != len("sha256:")+64 {
		errs = append(errs, fmt.Sprintf("image_digest %q is not a well-formed sha256 digest", p.ImageDigest))
	}
	if p.GeneratedBy == "" {
		errs = append(errs, "generated_by must be set (provenance is not optional)")
	}
	// §3.2 step 5: "Human review gate ... Never auto-promote." A profile
	// with no approver is, by definition, not an approved profile.
	if p.ApprovedBy == "" {
		errs = append(errs, "approved_by must be set: an unapproved profile must never reach the sandbox (§3.2 human review gate)")
	}
	if len(p.Tools) == 0 {
		errs = append(errs, "profile declares no tools: nothing to allow means nothing is callable, which is likely not intended")
	}

	seen := make(map[string]bool, len(p.Tools))
	for i, t := range p.Tools {
		prefix := fmt.Sprintf("tools[%d] (%s)", i, t.Name)

		if t.Name == "" {
			errs = append(errs, prefix+": name must be set")
		} else if seen[t.Name] {
			errs = append(errs, prefix+": duplicate tool name")
		}
		seen[t.Name] = true

		if len(t.Syscalls) == 0 {
			errs = append(errs, prefix+": syscalls list is empty — this tool could never do anything under a default-deny filter; confirm that's intended")
		}
		for _, sc := range t.Syscalls {
			if sc == "" {
				errs = append(errs, prefix+": empty syscall name in syscalls list")
			}
		}

		for _, e := range t.Effects {
			if !validEffects[e] {
				errs = append(errs, fmt.Sprintf("%s: unknown effect %q", prefix, e))
			}
		}

		for _, path := range append(append([]string{}, t.Filesystem.Read...), t.Filesystem.Write...) {
			if !strings.HasPrefix(path, "/") {
				errs = append(errs, fmt.Sprintf("%s: filesystem path %q must be absolute", prefix, path))
			}
			if strings.Contains(path, "..") {
				errs = append(errs, fmt.Sprintf("%s: filesystem path %q must not contain '..'", prefix, path))
			}
		}

		for _, n := range t.Network {
			if n.Host == "" {
				errs = append(errs, prefix+": network destination missing host")
			}
			if n.Port <= 0 || n.Port > 65535 {
				errs = append(errs, fmt.Sprintf("%s: network destination %q has invalid port %d", prefix, n.Host, n.Port))
			}
			if n.Proto != "tcp" && n.Proto != "udp" {
				errs = append(errs, fmt.Sprintf("%s: network destination %q has unsupported proto %q (only tcp/udp)", prefix, n.Host, n.Proto))
			}
		}

		if t.MaxDurationMS <= 0 {
			errs = append(errs, prefix+": max_duration_ms must be positive")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
