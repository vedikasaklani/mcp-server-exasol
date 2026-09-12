package compile

import (
	"fmt"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"mcp-warden/sandbox/profile"
)

// CanarySyscall is a syscall that must never appear in any CapabilityProfile
// and is therefore always denied by every compiled policy. The runtime's
// boot-time self-test (design note §4) invokes it inside a freshly confined
// container and asserts it gets errnoEPERM back — proving enforcement is
// actually active, not just requested, before the supervisor accepts real
// traffic. reboot(2) is a safe choice: no legitimate MCP tool ever needs it,
// and it's dangerous enough that no profile should ever declare it anyway.
const CanarySyscall = "reboot"

// errnoEPERM is the value CLAUDE.md's non-negotiable requires unlisted
// syscalls to return: "Unlisted syscalls return EPERM, not SIGSYS — a
// killed process loses the error context that makes violations
// diagnosable." Kept as its own uint so DefaultErrnoRet can point at it.
var errnoEPERM = uint(syscall.EPERM)

// compileSeccomp turns one tool's declared syscall allowlist into an OCI
// runtime-spec LinuxSeccomp document. This deliberately does NOT hand-roll
// a BPF program: it emits the structured OCI form and lets the container
// runtime's own seccomp compiler (already exercised by every other gVisor
// deployment) do the translation. See design note §2(a) — whether runsc
// actually enforces this against the workload with the expected errno is
// an open verification item, not an assumption this package makes.
func compileSeccomp(t profile.Tool) (*specs.LinuxSeccomp, error) {
	if len(t.Syscalls) == 0 {
		return nil, fmt.Errorf("compile: tool %q has no allowed syscalls", t.Name)
	}

	names := make([]string, 0, len(t.Syscalls))
	seen := make(map[string]bool, len(t.Syscalls))
	for _, sc := range t.Syscalls {
		if sc == CanarySyscall {
			return nil, fmt.Errorf("compile: tool %q declares %q, which is reserved as the enforcement canary and must never be allowed", t.Name, CanarySyscall)
		}
		if seen[sc] {
			continue
		}
		seen[sc] = true
		names = append(names, sc)
	}

	return &specs.LinuxSeccomp{
		DefaultAction:   specs.ActErrno,
		DefaultErrnoRet: &errnoEPERM,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  names,
				Action: specs.ActAllow,
			},
		},
	}, nil
}
