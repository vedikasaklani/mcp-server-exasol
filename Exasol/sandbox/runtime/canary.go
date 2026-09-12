package runtime

import (
	"context"
	"fmt"

	"mcp-warden/sandbox/compile"
)

// runCanaryCheck asserts that confinement is actually active, not just
// requested. It probes compile.CanarySyscall — a syscall reserved by the
// compile package and guaranteed never to appear in any allowed profile —
// and requires the kernel to deny it with EPERM. Anything else (success,
// a different errno, no denial at all) means the confinement we thought we
// applied did not take effect, and the caller must not proceed to READY.
//
// This exists because "we called Create() with a seccomp+Landlock policy"
// and "this container is actually confined" are different claims, and only
// the second one is the one CLAUDE.md's non-negotiables are about. See
// design note §4 and the open verification item on whether runsc enforces
// an OCI-spec seccomp policy against the workload the way this package
// assumes.
func runCanaryCheck(ctx context.Context, rt ContainerRuntime, id string) error {
	d, err := rt.ProbeSyscall(ctx, id, compile.CanarySyscall)
	if err != nil {
		return fmt.Errorf("runtime: canary probe failed to execute: %w", err)
	}
	if !d.Occurred {
		return fmt.Errorf("runtime: canary syscall %q was NOT denied — confinement is not active", compile.CanarySyscall)
	}
	if d.Kind != DenialKindSeccomp {
		return fmt.Errorf("runtime: canary syscall %q was denied by %q, expected seccomp", compile.CanarySyscall, d.Kind)
	}
	const epermErrno = 1 // syscall.EPERM; see sandbox/compile/seccomp.go's errnoEPERM
	if d.Errno != epermErrno {
		return fmt.Errorf("runtime: canary syscall %q was denied with errno %d, want EPERM (%d) per CLAUDE.md non-negotiable", compile.CanarySyscall, d.Errno, epermErrno)
	}
	return nil
}
