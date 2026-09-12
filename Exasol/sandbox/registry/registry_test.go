package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The property every test here defends: telemetry is best-effort, and a
// telemetry service that is slow, broken, or absent must never become a
// way to break confinement. A sandbox that stops working because an
// analytics database is down would be a worse tool than one with no
// analytics at all.

func TestDisabledClientIsANoOp(t *testing.T) {
	c := New("")
	if c.Enabled() {
		t.Fatal("a client with no base URL must not be enabled")
	}
	// None of these may panic or block; all are no-ops.
	if id := c.Resolve(context.Background(), "npm:x", "npm", "1.0.0"); id != "" {
		t.Errorf("Resolve on a disabled client = %q, want empty", id)
	}
	c.PostToolDiscovery("srv", []ToolInfo{{Name: "t"}}, "observed")
	c.PostRuntimeEvent("srv", RuntimeEvent{EventID: "e"})
	c.PostRuntimeFinding("srv", RuntimeFinding{Detector: "d", Severity: "high"})
	if err := c.PostSession(context.Background(), "srv", SessionSummary{}); err != nil {
		t.Errorf("PostSession on a disabled client = %v, want nil", err)
	}
}

func TestResolveReturnsEmptyWhenServiceIsDown(t *testing.T) {
	// Pointed at a port nothing is listening on: the caller must get ""
	// and carry on, not an error it has to handle or a hang.
	c := New("http://127.0.0.1:1")
	c.http.Timeout = 200 * time.Millisecond

	done := make(chan string, 1)
	go func() { done <- c.Resolve(context.Background(), "npm:x", "npm", "") }()
	select {
	case id := <-done:
		if id != "" {
			t.Errorf("Resolve against a dead service = %q, want empty", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Resolve blocked past its timeout — telemetry must never stall a load")
	}
	if !c.Unreachable() {
		t.Error("Unreachable() should be true after a failed call")
	}
}

func TestWritesDoNotBlockOnASlowService(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the request open
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(release)

	c := New(srv.URL)
	start := time.Now()
	c.PostRuntimeEvent("srv", RuntimeEvent{EventID: "e1", ToolName: "echo"})
	c.PostRuntimeFinding("srv", RuntimeFinding{Detector: "path-drift", Severity: "critical"})
	c.PostToolDiscovery("srv", []ToolInfo{{Name: "echo"}}, "observed")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fire-and-forget writes took %v against a hung service; they must return immediately", elapsed)
	}
}

func TestResolveParsesServerID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/servers/resolve" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["source"] != "npm:@scope/pkg" || body["kind"] != "npm" || body["ref"] != "2.1.0" {
			t.Errorf("request body = %+v, want the source/kind/ref passed in", body)
		}
		json.NewEncoder(w).Encode(map[string]string{"server_id": "srv-123"})
	}))
	defer srv.Close()

	c := New(srv.URL)
	if id := c.Resolve(context.Background(), "npm:@scope/pkg", "npm", "2.1.0"); id != "srv-123" {
		t.Errorf("Resolve = %q, want srv-123", id)
	}
	if c.Unreachable() {
		t.Error("Unreachable() should be false after a successful call")
	}
}

func TestResolveAsSendsCanonicalServerID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["canonical_server_id"] != "pg-server-1" {
			t.Fatalf("canonical_server_id = %q, want pg-server-1", body["canonical_server_id"])
		}
		json.NewEncoder(w).Encode(map[string]string{"server_id": body["canonical_server_id"]})
	}))
	defer srv.Close()

	c := New(srv.URL)
	if id := c.ResolveAs(context.Background(), "repo", "command", "", "pg-server-1"); id != "pg-server-1" {
		t.Fatalf("ResolveAs = %q, want pg-server-1", id)
	}
}

func TestPostSessionIsSynchronousAndSurfacesErrors(t *testing.T) {
	// The session summary is the one write with no second chance — it is
	// sent while the console is tearing down — so unlike the others it
	// must block and report failure rather than vanish into a goroutine.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL)
	err := c.PostSession(context.Background(), "srv", SessionSummary{SessionID: "s1"})
	if err == nil {
		t.Fatal("PostSession swallowed a 500; the caller needs to know the summary was lost")
	}
}

func TestRuntimeEventCarriesSandboxMetrics(t *testing.T) {
	// Guards the field mapping: these columns are the difference between
	// an audit trail that says a call happened and one that says what the
	// call did.
	var got map[string]any
	var mu sync.Mutex
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Events []map[string]any `json:"events"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.Events) > 0 {
			got = body.Events[0]
		}
		close(done)
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.PostRuntimeEvent("srv", RuntimeEvent{
		EventID: "e1", ToolName: "echo", SyscallCount: 1500, DistinctPaths: 42,
		FileReadBytes: 900, ProcessSpawns: 1, SeccompDenials: 1, Decision: "BLOCKED",
	})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("event was never sent")
	}

	mu.Lock()
	defer mu.Unlock()
	for field, want := range map[string]float64{
		"syscall_count": 1500, "distinct_paths": 42,
		"file_read_bytes": 900, "process_spawns": 1, "seccomp_denials": 1,
	} {
		if got[field] != want {
			t.Errorf("%s = %v, want %v", field, got[field], want)
		}
	}
	if got["decision"] != "BLOCKED" {
		t.Errorf("decision = %v, want BLOCKED", got["decision"])
	}
}
