package compile

import (
	"fmt"
	"sort"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/profile"
)

// Session compiles the union of every tool in a CapabilityProfile into the
// single CompiledPolicy that gets applied once, at container creation
// (design note §6.2's lifecycle: "session start → container created,
// profile loaded, seccomp + landlock applied"). This is the artifact
// runtime.EnforcingSupervisor.NewContainer actually consumes.
//
// Per-tool compilation (Tool, Profile) exists for diagnostics, but is not
// what gets enforced: a container hosts a long-running server process
// serving every tool in the profile over its lifetime, and a seccomp
// filter can only be tightened by stacking additional filters on top of
// an already-applied one — never loosened. Since which tool the next
// request will call isn't known at container-creation time, v0 applies
// the union up front rather than attempting per-request filter swaps,
// which would need a cooperating in-process shim inside a server v0 does
// not control.
func Session(p *profile.CapabilityProfile, opts Options) (*CompiledPolicy, error) {
	if len(p.Tools) == 0 {
		return nil, fmt.Errorf("compile: profile %s has no tools to compile a session policy from", p.ImageDigest)
	}

	syscalls := make(map[string]bool)
	fsAccess := make(map[string]LandlockAccess)
	netDests := make(map[profile.NetworkDestination]bool)
	toolNames := make([]string, 0, len(p.Tools))

	for _, t := range p.Tools {
		toolNames = append(toolNames, t.Name)

		for _, sc := range t.Syscalls {
			if sc == CanarySyscall {
				return nil, fmt.Errorf("compile: tool %q declares %q, which is reserved as the enforcement canary and must never be allowed", t.Name, CanarySyscall)
			}
			syscalls[sc] = true
		}
		for _, path := range t.Filesystem.Read {
			fsAccess[path] |= AccessRead
		}
		for _, path := range t.Filesystem.Write {
			fsAccess[path] |= AccessWrite
		}
		for _, n := range t.Network {
			netDests[n] = true
		}
	}

	if len(syscalls) == 0 {
		return nil, fmt.Errorf("compile: profile %s has no allowed syscalls across any tool", p.ImageDigest)
	}

	names := make([]string, 0, len(syscalls))
	for n := range syscalls {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic output: same profile always compiles to the same bytes

	seccomp := &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoEPERM,
		Syscalls: []specs.LinuxSyscall{
			{Names: names, Action: specs.ActAllow},
		},
	}

	paths := make([]string, 0, len(fsAccess))
	for path := range fsAccess {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	rules := make([]LandlockRule, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, LandlockRule{Path: path, Access: fsAccess[path]})
	}

	dests := make([]profile.NetworkDestination, 0, len(netDests))
	for d := range netDests {
		dests = append(dests, d)
	}
	sort.Slice(dests, func(i, j int) bool {
		if dests[i].Host != dests[j].Host {
			return dests[i].Host < dests[j].Host
		}
		if dests[i].Port != dests[j].Port {
			return dests[i].Port < dests[j].Port
		}
		return dests[i].Proto < dests[j].Proto
	})

	sort.Strings(toolNames)

	return &CompiledPolicy{
		ToolNames: toolNames,
		Seccomp:   seccomp,
		Landlock: LandlockRuleset{
			Rules:     rules,
			MinABI:    1,
			AppliesTo: LandlockTargetGuest,
		},
		Network: NetworkConfig{
			Mode:                NetworkModeNone,
			AllowedDestinations: dests,
			BrokerSocketPath:    opts.BrokerSocketPath,
		},
	}, nil
}
