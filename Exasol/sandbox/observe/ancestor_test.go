package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDropTraversalAncestors_RemovesParentsOfGrantedPaths(t *testing.T) {
	all := []string{"/home", "/home/u", "/home/u/app/node_modules/zod", "/usr/lib/libc.so.6"}
	kept, dropped := dropTraversalAncestors(all, all)

	if contains(kept, "/home") || contains(kept, "/home/u") {
		t.Fatalf("traversal-only parents must be dropped, kept=%v", kept)
	}
	if !contains(kept, "/home/u/app/node_modules/zod") {
		t.Fatalf("the actual grant must survive, kept=%v", kept)
	}
	if !contains(kept, "/usr/lib/libc.so.6") {
		t.Fatalf("a path with no granted descendants must survive, kept=%v", kept)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected 2 dropped ancestors, got %v", dropped)
	}
}

func TestDropTraversalAncestors_IsDirectoryWise(t *testing.T) {
	all := []string{"/usr/lib", "/usr/libexec/thing"}
	kept, _ := dropTraversalAncestors(all, all)
	if !contains(kept, "/usr/lib") {
		t.Fatalf("/usr/lib is not an ancestor of /usr/libexec/thing and must be kept, got %v", kept)
	}
}

func TestDropTraversalAncestors_ConsidersWriteSetWhenNarrowingReads(t *testing.T) {
	read := []string{"/tmp"}
	all := []string{"/tmp", "/tmp/served"}
	kept, dropped := dropTraversalAncestors(read, all)
	if len(kept) != 0 || len(dropped) != 1 {
		t.Fatalf("/tmp must be dropped because /tmp/served is granted; kept=%v dropped=%v", kept, dropped)
	}
}

func TestCollapseToShortest_KeepsDeclaredDirectoryOverNestedFile(t *testing.T) {
	got := collapseToShortest([]string{"/data/dir/file.txt", "/data/dir", "/other"})
	if contains(got, "/data/dir/file.txt") {
		t.Fatalf("a file inside a declared writable dir is redundant, got %v", got)
	}
	if !contains(got, "/data/dir") || !contains(got, "/other") {
		t.Fatalf("expected /data/dir and /other, got %v", got)
	}
}

// This is the regression test for the real bug found by running the
// pipeline against a live Node MCP server: Node stats every parent
// directory during module resolution, so /home showed up as an observed
// path. Left in the profile, mount coalescing would then collapse every
// precise node_modules grant into a read-only bind mount of the entire
// home directory — silently turning a tight allowlist into full home
// exposure.
func TestGenerateProfile_DoesNotGrantHomeBecauseAParentWasStatted(t *testing.T) {
	home := t.TempDir()
	deep := filepath.Join(home, "user", "app", "node_modules", "zod")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, "user", ".ssh")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}

	observed := []string{
		home,
		filepath.Join(home, "user"),
		filepath.Join(home, "user", "app"),
		filepath.Join(home, "user", "app", "node_modules"),
		deep,
	}
	cand, err := GenerateProfile(reportForProfile(t, observed), ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	read := cand.Profile.Tools[0].Filesystem.Read
	if len(read) != 1 || read[0] != deep {
		t.Fatalf("expected only the leaf grant to survive, got %v", read)
	}
	for _, p := range read {
		if strings.HasPrefix(secret, p+"/") {
			t.Fatalf("granted path %q would expose %q", p, secret)
		}
	}
	if len(cand.DroppedAncestors) != 4 {
		t.Fatalf("expected 4 traversal-only ancestors dropped, got %v", cand.DroppedAncestors)
	}
}

func TestGenerateProfile_FlagsBroadSystemRootGrants(t *testing.T) {
	// /etc exists on any Linux host and has no granted descendants here,
	// so it survives narrowing and must be flagged rather than silently
	// accepted.
	cand, err := GenerateProfile(reportForProfile(t, []string{"/etc"}), ProfileOptions{ToolName: "srv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !contains(cand.BroadGrants, "/etc") {
		t.Fatalf("granting a whole system root must be flagged, got %v", cand.BroadGrants)
	}
}
