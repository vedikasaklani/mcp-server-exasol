package compile

import (
	"mcp-warden/sandbox/profile"
)

// LandlockAccess is a bitmask of the access rights a rule grants. It
// deliberately mirrors only the base filesystem rights available since
// Landlock ABI 1 (kernel 5.13) — read and write. It does not attempt to
// model TRUNCATE (ABI 3 / kernel 6.2) or network rights (ABI 4 / kernel
// 6.7): see design note flag #1 on the ABI/kernel version this project's
// stated 6.1+ target actually gets (ABI 2, not the assumed ABI 3).
type LandlockAccess uint8

const (
	AccessRead LandlockAccess = 1 << iota
	AccessWrite
)

// LandlockRule is one path plus the access rights granted on it.
type LandlockRule struct {
	Path   string
	Access LandlockAccess
}

// LandlockRuleset is the backend-agnostic compiled form of a tool's
// filesystem allowlist. It intentionally does NOT depend on go-landlock's
// types here: compile stays a pure, dependency-light package, and it is
// runtime's job to decide where this ruleset actually gets applied.
//
// That "where" is unsettled by design, not by oversight — see design note
// flag #2: Landlock is a host-VFS LSM, and gVisor's sentry mediates the
// guest's file syscalls itself rather than passing them through to a real
// host VFS in the form Landlock would see. Applying this ruleset to the
// guest process may be a no-op. Until that's verified against the actual
// runsc version in use, treat AppliesTo as informational, and treat
// gVisor's own mount/rootfs configuration (not this ruleset) as the
// primary filesystem confinement mechanism for the guest.
type LandlockRuleset struct {
	Rules []LandlockRule
	// MinABI is the minimum Landlock ABI version this ruleset requires.
	// v0 only ever produces MinABI 1 (Landlock existed at all) because it
	// only uses read/write rights.
	MinABI int
	// AppliesTo documents which process this ruleset is meant to restrict.
	// "guest" is what §6.1 point 3 implies; "sentry" is the design note's
	// recommended fallback pending verification.
	AppliesTo LandlockTarget
}

// LandlockTarget names which process a LandlockRuleset is meant to
// restrict.
type LandlockTarget string

const (
	// LandlockTargetGuest restricts the sandboxed MCP server process
	// directly. Unverified against gVisor — see LandlockRuleset doc.
	LandlockTargetGuest LandlockTarget = "guest"
	// LandlockTargetSentry restricts the runsc sentry/gofer process,
	// protecting the host rather than narrowing the guest's per-tool
	// paths. Defense-in-depth, not a substitute for guest-level
	// filesystem confinement (which gVisor's own mounts must provide).
	LandlockTargetSentry LandlockTarget = "sentry"
)

// compileLandlock turns a tool's filesystem allowlist into a
// LandlockRuleset. Read and write paths are compiled as separate rules
// even when a path appears in both sets, mirroring §6.1.3's "read and
// write sets are separate." A tool with no declared paths compiles to an
// empty ruleset — that's a legitimate, maximally-restrictive outcome (a
// network-only tool, say), not an error.
func compileLandlock(t profile.Tool) LandlockRuleset {
	rules := make([]LandlockRule, 0, len(t.Filesystem.Read)+len(t.Filesystem.Write))
	for _, p := range t.Filesystem.Read {
		rules = append(rules, LandlockRule{Path: p, Access: AccessRead})
	}
	for _, p := range t.Filesystem.Write {
		rules = append(rules, LandlockRule{Path: p, Access: AccessWrite})
	}

	return LandlockRuleset{
		Rules:     rules,
		MinABI:    1,
		AppliesTo: LandlockTargetGuest,
	}
}
