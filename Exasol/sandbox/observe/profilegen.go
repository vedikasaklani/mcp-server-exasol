package observe

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mcp-warden/sandbox/profile"
)

// virtualPrefixes are filesystem trees the sandbox provides itself rather
// than bind-mounting from the host: /proc and /sys are mounted by the
// runtime, /dev's device nodes are created by it, and the scratch tmpfs
// and probe mount are sandbox infrastructure. A generated profile must not
// declare these as host paths to mount — doing so would either fail (the
// host path is not what the guest saw) or, worse, bind the host's real
// /proc into the sandbox.
var virtualPrefixes = []string{
	"/proc", "/sys", "/dev", "/tmp/scratch", "/.mcp-warden",
}

// broadRoots are directories that must never be granted wholesale. A
// profile that mounts one of these read-only hands the sandbox every
// user's files, every system credential, or the entire OS image — which
// defeats the point of a per-server allowlist even though every path in
// it was genuinely "observed".
var broadRoots = map[string]bool{
	"/": true, "/home": true, "/root": true, "/etc": true,
	"/usr": true, "/var": true, "/opt": true, "/srv": true, "/mnt": true,
}

// Widening records one place where profile generation granted access
// broader than what was actually observed. Every entry is something a
// human reviewer (§3.2 step 5) needs to see before approving, because it
// is a deliberate over-grant made for reviewability, not an observation.
type Widening struct {
	Granted  string
	CoveredN int
	Examples []string
}

// ProfileOptions configures profile generation.
type ProfileOptions struct {
	// ToolName is the tool entry name in the generated profile.
	ToolName string
	// ImageDigest identifies the artifact this profile is bound to. If
	// empty, it's derived from the target's entrypoint binary contents
	// and argv — a real, checkable identity for a locally-installed
	// server, standing in for the image digest a registry would provide.
	ImageDigest string
	// RollupDepth, when > 0, collapses observed paths to that many
	// leading directory components. A real Node server touches ~600
	// files; a 600-entry allowlist is not something a human can
	// meaningfully review, and §3.2's approval gate is worthless if the
	// artifact being approved is unreadable. Rollup trades precision for
	// reviewability, and every trade it makes is reported in Widenings.
	RollupDepth int
	// WritePaths are prefixes the server legitimately writes to. Observed
	// write intent is unreliable on its own (it's inferred from syscall
	// names, not open flags), so the operator declares the write set
	// explicitly rather than having it guessed.
	WritePaths []string
	// MountBudget caps how many paths the profile may grant, because a
	// granted path becomes a bind mount and gVisor donates one file
	// descriptor per mount to the sandbox. Past roughly 236 mounts the
	// sandbox process dies during boot with no error message at all —
	// measured on gVisor release-20260817, where 233 mounts booted and 240
	// did not.
	//
	// Zero means DefaultMountBudget. A profile that cannot be fitted under
	// the budget without granting a whole system tree is left over budget
	// rather than widened into one; runsc.GenerateSpec then refuses it,
	// which is the right outcome — an unbootable container that says why
	// beats a confined one that grants /usr.
	MountBudget int
}

// DefaultMountBudget leaves a deliberate margin below the measured
// ~236-mount ceiling: the ceiling is a property of a specific gVisor
// build, and a profile generated on one host should still boot on another.
const DefaultMountBudget = 200

// ProfileCandidate is a generated, unapproved CapabilityProfile plus the
// context a reviewer needs to judge it.
type ProfileCandidate struct {
	Profile   *profile.CapabilityProfile
	Widenings []Widening
	// SkippedVirtual lists observed paths excluded as sandbox-provided
	// virtual filesystems.
	SkippedVirtual []string
	// SkippedMissing lists observed paths that no longer exist on the
	// host and so cannot be mounted (transient files, deleted temporaries).
	SkippedMissing []string
	// DroppedAncestors lists paths that were observed but dropped because
	// they are merely parent directories of something else that IS
	// granted. This is a narrowing, not a widening — see dropTraversalAncestors.
	DroppedAncestors []string
	// BroadGrants lists granted paths that expose a whole system tree.
	// Any entry here should block approval until the profile is edited.
	BroadGrants []string
	// AddedForExec lists paths added that were never observed but are
	// required for the entrypoint to execute at all — currently the ELF
	// interpreter. See entrypointInterpreters.
	AddedForExec []string
}

// GenerateProfile turns an observation Report into a candidate
// CapabilityProfile (§3.2 step 4).
//
// The returned profile deliberately has an empty ApprovedBy and will
// therefore FAIL profile.Validate() until an operator fills it in. That is
// the point: §3.2 step 5 says "Human review gate. An operator approves or
// edits the profile. Never auto-promote — a server that exfiltrates during
// profiling would have the exfiltration baked into its allowlist." Making
// the generated artifact structurally invalid until a human signs it turns
// that rule from documentation into a mechanism.
func GenerateProfile(r *Report, opts ProfileOptions) (*ProfileCandidate, error) {
	if r == nil {
		return nil, fmt.Errorf("observe: nil report")
	}
	if len(r.Syscalls) == 0 {
		return nil, fmt.Errorf("observe: report contains no observed syscalls; nothing to build a profile from")
	}
	toolName := opts.ToolName
	if toolName == "" {
		toolName = "observed"
	}

	digest := opts.ImageDigest
	if digest == "" {
		var err error
		digest, err = deriveDigest(r.Target)
		if err != nil {
			return nil, fmt.Errorf("observe: derive image digest: %w", err)
		}
	}

	cand := &ProfileCandidate{}

	// Filesystem: filter, then optionally roll up.
	var candidatePaths []string
	for _, p := range sortedKeys(r.Paths) {
		if isVirtual(p) {
			cand.SkippedVirtual = append(cand.SkippedVirtual, p)
			continue
		}
		if _, err := os.Stat(p); err != nil {
			cand.SkippedMissing = append(cand.SkippedMissing, p)
			continue
		}
		candidatePaths = append(candidatePaths, p)
	}

	// A dynamically linked entrypoint needs its ELF interpreter, and that
	// path is NEVER observable: the kernel (here, gVisor's sentry) maps the
	// loader inside execve(2) rather than through an openat the guest
	// makes. Omitting it produces an execve that fails with ENOENT naming
	// the binary — which is present — making it look like the mount failed.
	// Detect it from the ELF header instead of hoping it shows up.
	for _, interp := range entrypointInterpreters(r.Target) {
		if !contains(candidatePaths, interp) {
			candidatePaths = append(candidatePaths, interp)
			cand.AddedForExec = append(cand.AddedForExec, interp)
		}
	}

	granted := candidatePaths
	if opts.RollupDepth > 0 {
		granted, cand.Widenings = rollup(candidatePaths, opts.RollupDepth)
	}

	readSet, writeSet := splitReadWrite(granted, opts.WritePaths)

	// Drop read grants that exist only because something deeper was
	// reached through them, and collapse redundant write grants. Doing
	// this here rather than leaving it to mount coalescing is essential:
	// coalescing keeps the *shortest* covering path, so leaving "/home"
	// in the read set would silently collapse every precise node_modules
	// grant into a read-only bind mount of the entire home directory.
	all := append(append([]string{}, readSet...), writeSet...)
	readSet, cand.DroppedAncestors = dropTraversalAncestors(readSet, all)
	writeSet = collapseToShortest(writeSet)

	// Fit the read set to the mount budget. This runs after ancestor
	// dropping on purpose: dropping ancestors is what produces the
	// hundreds of individual leaf-file grants in the first place, and the
	// budget is the constraint that says how many of those the runtime can
	// actually carry.
	budget := opts.MountBudget
	if budget == 0 {
		budget = DefaultMountBudget
	}
	if budget > 0 {
		var budgetWidenings []Widening
		readSet, budgetWidenings = fitToMountBudget(readSet, budget-len(writeSet))
		cand.Widenings = append(cand.Widenings, budgetWidenings...)
	}

	for _, p := range append(append([]string{}, readSet...), writeSet...) {
		if broadRoots[p] {
			cand.BroadGrants = append(cand.BroadGrants, p)
		}
	}

	syscalls := r.SyscallNames()

	maxDuration := int(r.Duration/time.Millisecond) * 4
	if maxDuration < 5000 {
		maxDuration = 5000
	}
	if maxDuration > 60000 {
		maxDuration = 60000
	}

	cand.Profile = &profile.CapabilityProfile{
		ProfileVersion: "1.0",
		ImageDigest:    digest,
		GeneratedBy:    "learning_mode",
		// Left empty on purpose — see this function's doc comment.
		ApprovedBy:   "",
		ParallelSafe: false,
		// Pin what was actually observed, so the enforcing run can refuse
		// a binary that is not the one this profile was generated from.
		// The interpreter is pinned separately because it never appears
		// in the trace this profile was built from: the sentry maps it
		// inside execve.
		Entrypoint: measureEntrypoint(r.Target),
		Tools: []profile.Tool{{
			Name:          toolName,
			Effects:       inferEffects(writeSet),
			Syscalls:      syscalls,
			Filesystem:    profile.FilesystemAccess{Read: readSet, Write: writeSet},
			MaxDurationMS: maxDuration,
		}},
	}
	return cand, nil
}

// measureEntrypoint hashes the observed entrypoint and its ELF
// interpreter for embedding in the candidate profile. It returns nil
// rather than an error if the binary cannot be hashed: a profile that
// cannot pin a digest is still a usable profile, and failing generation
// over it would make the whole pipeline depend on a strengthening
// measure rather than on a required one.
func measureEntrypoint(t Target) *profile.EntrypointAttestation {
	if len(t.Command) == 0 {
		return nil
	}
	bin := t.Command[0]
	if resolved, err := exec.LookPath(bin); err == nil {
		bin = resolved
	}
	sum, err := sha256File(bin)
	if err != nil {
		return nil
	}
	att := &profile.EntrypointAttestation{Path: bin, SHA256: sum}
	if interp, err := elfInterpreter(bin); err == nil && interp != "" {
		att.Interpreter = interp
		if isum, err := sha256File(interp); err == nil {
			att.InterpreterSHA256 = isum
		}
	}
	return att
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// entrypointInterpreters returns the ELF interpreter(s) the target's
// entrypoint binary needs, if any. A statically linked binary needs none
// and yields nothing.
func entrypointInterpreters(t Target) []string {
	if len(t.Command) == 0 {
		return nil
	}
	bin := t.Command[0]
	if resolved, err := exec.LookPath(bin); err == nil {
		bin = resolved
	}
	interp, err := elfInterpreter(bin)
	if err != nil || interp == "" {
		return nil
	}
	out := []string{interp}
	// The interpreter path is frequently reached through a symlinked
	// directory (/lib64 -> usr/lib on many distros). Grant the resolved
	// real path too, so the mount works whichever the guest resolves to.
	if real, err := filepath.EvalSymlinks(interp); err == nil && real != interp {
		out = append(out, real)
	}
	return out
}

func elfInterpreter(binary string) (string, error) {
	f, err := elf.Open(binary)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\x00"), nil
	}
	return "", nil
}

func isVirtual(p string) bool {
	for _, v := range virtualPrefixes {
		if p == v || strings.HasPrefix(p, v+"/") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]*PathAccess) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rollup collapses paths to depth leading components, returning the
// granted set plus a report of every collapse that covered more than one
// observed path.
func rollup(paths []string, depth int) ([]string, []Widening) {
	groups := map[string][]string{}
	for _, p := range paths {
		groups[truncatePath(p, depth)] = append(groups[truncatePath(p, depth)], p)
	}

	granted := make([]string, 0, len(groups))
	for g := range groups {
		granted = append(granted, g)
	}
	sort.Strings(granted)

	var widenings []Widening
	for _, g := range granted {
		members := groups[g]
		if len(members) == 1 && members[0] == g {
			continue // granted exactly what was observed; nothing widened
		}
		examples := members
		if len(examples) > 3 {
			examples = examples[:3]
		}
		widenings = append(widenings, Widening{
			Granted:  g,
			CoveredN: len(members),
			Examples: examples,
		})
	}
	return granted, widenings
}

// truncatePath keeps the first depth path components. A path with fewer
// components than depth is returned unchanged — rollup never invents a
// broader parent than the path itself.
func truncatePath(p string, depth int) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) <= depth {
		return p
	}
	return "/" + strings.Join(parts[:depth], "/")
}

// splitReadWrite assigns each granted path to the write set if it falls
// under an operator-declared write prefix, and to the read set otherwise.
// Observed access kind is deliberately not used to grant writes: it's
// inferred from syscall names rather than open(2) flags, and guessing a
// write grant wrong in the permissive direction is exactly the mistake
// this whole layer exists to prevent.
func splitReadWrite(granted, writePrefixes []string) (read, write []string) {
	for _, p := range granted {
		isWrite := false
		for _, w := range writePrefixes {
			if p == w || strings.HasPrefix(p, strings.TrimSuffix(w, "/")+"/") {
				isWrite = true
				break
			}
		}
		if isWrite {
			write = append(write, p)
		} else {
			read = append(read, p)
		}
	}
	// A declared write prefix that was never observed is still granted:
	// the operator asserted the server needs it, and a server that can't
	// write its scratch directory because profiling happened not to
	// exercise that path is a profile that breaks in production.
	for _, w := range writePrefixes {
		if !contains(write, w) {
			write = append(write, w)
		}
	}
	sort.Strings(read)
	sort.Strings(write)
	return read, write
}

// dropTraversalAncestors removes any path in paths that is a strict
// ancestor of some other granted path. Such a path was almost always
// observed because the process walked *through* it (Node stats every
// parent directory while resolving modules), not because it needs the
// directory's contents.
//
// Dropping it is a narrowing, and a safe one: bind-mounting
// /a/b/c/node_modules/zod still makes /a, /a/b, /a/b/c traversable inside
// the guest — they exist as mount points holding only what was actually
// granted. Keeping the ancestor instead would expose everything else that
// lives under it on the host.
func dropTraversalAncestors(paths, all []string) (kept, dropped []string) {
	for _, p := range paths {
		isAncestor := false
		for _, other := range all {
			if other != p && strings.HasPrefix(other, p+"/") {
				isAncestor = true
				break
			}
		}
		if isAncestor {
			dropped = append(dropped, p)
		} else {
			kept = append(kept, p)
		}
	}
	return kept, dropped
}

// fitToMountBudget collapses directories until the granted set is no
// larger than budget, and reports every collapse it made.
//
// The greedy choice — collapse whichever directory currently eliminates
// the most entries — matters. A blanket "roll everything up to depth N"
// widens uniformly, including the singleton grants that cost one mount
// each and are the most precise part of the profile. This instead spends
// precision only where precision is expensive: a dependency directory
// contributing fifty observed files becomes one mount, while a lone
// /etc/ssl/openssl.cnf stays exactly itself.
//
// A directory in broadRoots is never collapsed to, whatever it would
// save. Fitting the budget is worth widening a package directory; it is
// not worth granting /usr, and a profile that cannot fit without doing so
// is one a human should look at rather than one this function should
// quietly produce.
func fitToMountBudget(paths []string, budget int) (kept []string, widenings []Widening) {
	current := append([]string(nil), paths...)
	sort.Strings(current)
	if budget <= 0 || len(current) <= budget {
		return current, nil
	}

	for len(current) > budget {
		groups := map[string][]string{}
		for _, p := range current {
			groups[path.Dir(p)] = append(groups[path.Dir(p)], p)
		}

		// Pick deterministically: most entries eliminated, ties broken by
		// the deeper (more specific) directory, then lexically.
		best, bestN := "", 0
		for _, dir := range sortedStringKeys(groups) {
			if dir == "/" || dir == "." || broadRoots[dir] {
				continue
			}
			n := 0
			for _, p := range current {
				if p == dir || strings.HasPrefix(p, dir+"/") {
					n++
				}
			}
			if n < 2 {
				continue
			}
			if n > bestN || (n == bestN && strings.Count(dir, "/") > strings.Count(best, "/")) {
				best, bestN = dir, n
			}
		}
		if best == "" {
			// Nothing further can be collapsed without granting a system
			// tree. Leave the set over budget; GenerateSpec will refuse it
			// with an explanation rather than producing a container that
			// dies silently.
			break
		}

		var next []string
		var covered []string
		for _, p := range current {
			if p == best || strings.HasPrefix(p, best+"/") {
				covered = append(covered, p)
				continue
			}
			next = append(next, p)
		}
		next = append(next, best)
		sort.Strings(next)
		current = next

		examples := covered
		if len(examples) > 3 {
			examples = examples[:3]
		}
		widenings = append(widenings, Widening{
			Granted:  best,
			CoveredN: len(covered),
			Examples: examples,
		})
	}
	return current, widenings
}

func sortedStringKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collapseToShortest keeps only the outermost path of each nested group —
// the opposite of dropTraversalAncestors, and correct for write grants:
// the operator declared a writable directory, so a separately listed file
// inside it is redundant rather than a broader grant.
func collapseToShortest(paths []string) []string {
	sorted := append([]string{}, paths...)
	sort.Strings(sorted)
	var kept []string
	for _, p := range sorted {
		covered := false
		for _, k := range kept {
			if p == k || strings.HasPrefix(p, k+"/") {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	return kept
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func inferEffects(writeSet []string) []profile.Effect {
	if len(writeSet) > 0 {
		return []profile.Effect{profile.EffectRead, profile.EffectWrite}
	}
	return []profile.Effect{profile.EffectRead}
}

// deriveDigest builds a stable sha256 identity for a locally-installed
// server from its entrypoint binary's contents plus its full argv. It is
// not a registry image digest, but it serves the same purpose the
// architecture asks a digest to serve: binding this profile to this exact
// artifact, so a changed binary doesn't silently inherit an approved
// profile.
func deriveDigest(t Target) (string, error) {
	h := sha256.New()
	for _, a := range t.Command {
		fmt.Fprintf(h, "%s\x00", a)
	}
	if len(t.Command) > 0 {
		bin := t.Command[0]
		if resolved, err := exec.LookPath(bin); err == nil {
			bin = resolved
		}
		if data, err := os.ReadFile(bin); err == nil {
			h.Write(data)
		}
		// An unreadable entrypoint (a shell builtin, an interpreter
		// resolved from PATH inside the sandbox) still yields a digest
		// over argv alone. That's weaker, but a weak identity is better
		// than refusing to profile at all — and the profile records what
		// it was generated from either way.
	}
	// Bind the primary script/module argument's contents too, when it
	// looks like a real file: for `node /path/server.js`, the interesting
	// artifact is server.js, not the node binary.
	for _, a := range t.Command[1:] {
		if filepath.IsAbs(a) {
			if data, err := os.ReadFile(a); err == nil {
				h.Write(data)
				break
			}
		}
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
