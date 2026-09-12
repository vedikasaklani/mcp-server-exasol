package analyze

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"mcp-warden/sandbox/profile"
)

// Baseline is what a server is *expected* to do. It has two halves, and
// keeping them distinct is the whole reason this type exists.
//
// The deterministic half comes from the CapabilityProfile a human
// approved: the syscall allowlist, the read and write path sets, the
// declared network destinations. Deviation from it is a fact, not an
// opinion, and detectors that measure it report Deterministic confidence.
//
// The statistical half is learned online from the session's own opening
// traffic — how many paths a typical request touches, how many bytes it
// moves. It exists because no profile schema can usefully declare "about
// four files per call", and because this system has to accept any MCP
// server pulled off the internet with no prior behavioural record.
// Deviation from it is an opinion, reported as Statistical confidence,
// and it is never allowed to produce a critical finding on its own.
type Baseline struct {
	Digest string `json:"image_digest"`
	// AllowedSyscalls is the union across every tool in the profile —
	// confinement is applied once per container (see compile.Session), so
	// the union is what the kernel actually enforces and therefore what
	// conformance must be measured against.
	AllowedSyscalls map[string]bool `json:"-"`
	ReadPaths       []string        `json:"read_paths"`
	WritePaths      []string        `json:"write_paths"`
	Network         []string        `json:"network"`
	// NetworkDeclared is false when the profile declares no destinations
	// at all, which is the common case and means *any* dial is a
	// deviation.
	NetworkDeclared bool           `json:"network_declared"`
	MaxDurationMS   map[string]int `json:"max_duration_ms"`
	Entrypoint      *profile.EntrypointAttestation

	// WarmupRequests is how many requests are consumed to learn the
	// statistical half before it starts producing findings.
	WarmupRequests int `json:"warmup_requests"`

	// measured is the entrypoint identity the monitor observed, retained
	// so newly created containers inherit it without re-hashing.
	measured *EntrypointIdentity
}

// Measured returns the entrypoint identity observed for this baseline, if
// one has been recorded.
func (b *Baseline) Measured() (EntrypointIdentity, bool) {
	if b.measured == nil {
		return EntrypointIdentity{}, false
	}
	return *b.measured, true
}

// BaselineFromProfile derives the deterministic half from an approved
// CapabilityProfile.
func BaselineFromProfile(p *profile.CapabilityProfile) *Baseline {
	b := &Baseline{
		Digest:          p.ImageDigest,
		AllowedSyscalls: map[string]bool{},
		MaxDurationMS:   map[string]int{},
		Entrypoint:      p.Entrypoint,
		WarmupRequests:  20,
	}
	readSet := map[string]bool{}
	writeSet := map[string]bool{}
	netSet := map[string]bool{}
	for _, t := range p.Tools {
		for _, s := range t.Syscalls {
			b.AllowedSyscalls[s] = true
		}
		for _, r := range t.Filesystem.Read {
			readSet[r] = true
		}
		for _, w := range t.Filesystem.Write {
			writeSet[w] = true
		}
		for _, n := range t.Network {
			b.NetworkDeclared = true
			netSet[n.Host+":"+itoa(n.Port)] = true
		}
		if t.MaxDurationMS > 0 {
			b.MaxDurationMS[t.Name] = t.MaxDurationMS
		}
	}
	b.ReadPaths = sortedKeys(readSet)
	b.WritePaths = sortedKeys(writeSet)
	b.Network = sortedKeys(netSet)
	return b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// AllowsRead reports whether p falls under a declared read path. Write
// paths imply read access: a process that may modify a file may
// obviously observe it, and treating a write grant as read-denied would
// produce a conformance finding on every normal write.
func (b *Baseline) AllowsRead(p string) bool {
	return underAny(p, b.ReadPaths) || underAny(p, b.WritePaths)
}

// AllowsWrite reports whether p falls under a declared write path.
func (b *Baseline) AllowsWrite(p string) bool { return underAny(p, b.WritePaths) }

// IsAncestorOfGrant reports whether some granted path lives beneath p.
//
// Such a directory exists inside the guest only because the profile
// granted something under it: mounting /a/b/c.js necessarily makes /a and
// /a/b exist as traversable directories. A server that opens or lists one
// of them has not reached outside its profile — it is looking at the
// mount topology this system built for it, and everything it can see
// there is, by construction, exactly what was granted.
//
// sandbox/observe drops these same ancestors from the grant set when
// generating a profile (see dropTraversalAncestors), for the same reason.
// Conformance has to apply the rule from the other side too, or every
// profile that grants individual files reports drift on the directories
// holding them.
func (b *Baseline) IsAncestorOfGrant(p string) bool {
	if p == "/" {
		return false
	}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for _, g := range b.ReadPaths {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	for _, g := range b.WritePaths {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	return false
}

// AllowsSyscall reports whether name is in the approved union. An empty
// allowlist means no profile was supplied (learning/observation mode), in
// which case conformance is not measurable and must not be reported as
// satisfied.
func (b *Baseline) AllowsSyscall(name string) bool {
	if len(b.AllowedSyscalls) == 0 {
		return true
	}
	return b.AllowedSyscalls[name]
}

// HasProfile reports whether a deterministic baseline exists at all.
func (b *Baseline) HasProfile() bool { return len(b.AllowedSyscalls) > 0 }

// underAny reports whether p is equal to, or contained by, any prefix.
// Containment is directory-wise: "/etc/sslx" is not under "/etc/ssl",
// which a naive strings.HasPrefix would get wrong in the direction that
// grants access.
func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if p == pre {
			return true
		}
		if pre == "/" {
			return true
		}
		if strings.HasPrefix(p, strings.TrimSuffix(pre, "/")+"/") {
			return true
		}
	}
	return false
}

// EntrypointIdentity is the measured identity of the code the container
// actually started: the executable and, for a dynamically linked one, the
// interpreter that maps it.
//
// The interpreter is included because it is invisible everywhere else.
// The sentry maps ld.so inside execve, so it never appears in a syscall
// trace — this project already learned that the hard way when enforced
// runs failed with an ENOENT naming the wrong file. Code that never shows
// up in observation is exactly the code worth pinning by digest.
type EntrypointIdentity struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	Interpreter       string `json:"interpreter,omitempty"`
	InterpreterSHA256 string `json:"interpreter_sha256,omitempty"`
	Err               string `json:"error,omitempty"`
}

// MeasureEntrypoint hashes an executable and its ELF interpreter.
func MeasureEntrypoint(execPath string) EntrypointIdentity {
	id := EntrypointIdentity{Path: execPath}
	sum, err := sha256File(execPath)
	if err != nil {
		id.Err = err.Error()
		return id
	}
	id.SHA256 = sum
	if interp, err := elfInterpreter(execPath); err == nil && interp != "" {
		id.Interpreter = interp
		if isum, err := sha256File(interp); err == nil {
			id.InterpreterSHA256 = isum
		}
	}
	return id
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

func elfInterpreter(p string) (string, error) {
	f, err := elf.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, prog.Filesz)
		if _, err := io.ReadFull(prog.Open(), buf); err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\x00"), nil
	}
	return "", nil
}

// sensitivePatterns are credential- and secret-shaped locations. These
// are deliberately specific rather than broad prefixes: an earlier
// iteration used "/home" and produced 543 findings on a single reference
// run, none of them meaningful, which is how a detector gets turned off
// and stays off.
var sensitivePatterns = []string{
	"/.ssh/", "/.aws/", "/.kube/", "/.gnupg/", "/.netrc",
	"/.git-credentials", "/.docker/config.json", "/.npmrc", "/.pypirc",
	"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/",
	"/var/run/secrets", "/run/secrets", "/proc/1/environ",
	"/.config/gh/hosts.yml", "/.gitconfig",
	"id_rsa", "id_ed25519", "credentials.json", ".pem",
	".env", "secrets.yaml", "secrets.yml",
}

// IsSensitivePath reports whether p looks like a credential store. This
// is pattern matching, and it is honest about being pattern matching:
// detectors built on it report Heuristic confidence unless the path also
// violated the profile, in which case the profile violation is the
// deterministic part of the claim.
func IsSensitivePath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	for _, pat := range sensitivePatterns {
		if strings.HasPrefix(pat, "/") {
			if strings.Contains(lower, pat) {
				return true
			}
			continue
		}
		if strings.HasSuffix(base, pat) || base == pat {
			return true
		}
	}
	return false
}

// sandboxProvidedPrefixes are filesystem trees the sandbox mounts itself
// rather than binding in from a profile: /proc and /sys come from the
// runtime, /dev's nodes are created by it, and the scratch tmpfs and the
// probe mount are warden's own infrastructure.
//
// A CapabilityProfile structurally cannot grant these — sandbox/observe's
// profile generator filters them out, because declaring them would either
// fail or bind the host's real /proc into the guest. Conformance must
// apply the same rule from the other side: a path no profile is allowed
// to contain cannot be evidence that this profile is missing it. Without
// this, every language runtime's startup reads (/proc/meminfo,
// /proc/self/maps, /sys/kernel/mm/...) are reported as reads outside the
// declared set, which is a high-severity finding on every healthy server
// — the exact way a detector earns its way into being switched off.
//
// This hides nothing that matters: these paths are still recorded, still
// counted, and still inspected by the detectors whose question is about
// content rather than conformance (see IsSensitivePath, which knows about
// /proc/1/environ).
var sandboxProvidedPrefixes = []string{
	"/proc", "/sys", "/dev", "/tmp/scratch", "/.mcp-warden",
}

// IsSandboxProvidedPath reports whether p belongs to a tree the sandbox
// provides rather than one a profile grants.
func IsSandboxProvidedPath(p string) bool {
	for _, prefix := range sandboxProvidedPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// InfrastructureProcesses are process names belonging to warden's own
// instrumentation rather than to the server under test.
//
// The canary shim runs as "probe": it is the first thing in every
// container, it deliberately attempts a forbidden syscall to prove the
// seccomp filter is live, and it then execs the real entrypoint. Counting
// its syscalls against the server's profile makes every container report
// a denied syscall the profile never declared — which is warden observing
// its own safety check and calling it a deviation.
//
// gVisor's strace records the process name per line and it changes at
// execve, so the split is exact rather than heuristic: 44 lines of probe
// followed by several thousand of node, in the reference run this was
// derived from.
var InfrastructureProcesses = map[string]bool{
	"probe": true,
}

// moduleDirs are the package directories whose contents constitute a
// server's dependency set. A file loaded from one of these that was not
// present when the profile was approved is a dependency that changed
// after review — the supply-chain event this system exists to notice.
var moduleDirs = []string{"/node_modules/", "/site-packages/", "/dist-packages/", "/vendor/", "/.cargo/registry/", "/gems/"}

// IsModulePath reports whether p is inside a dependency tree.
func IsModulePath(p string) bool {
	for _, d := range moduleDirs {
		if strings.Contains(p, d) {
			return true
		}
	}
	return false
}

// IsSharedObject reports whether p is a loadable native library. Native
// code loaded at runtime bypasses every language-level review a
// dependency audit performs.
func IsSharedObject(p string) bool {
	base := path.Base(p)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.") || strings.HasSuffix(base, ".node") || strings.HasSuffix(base, ".dylib")
}
