package profile

import (
	"strings"
	"testing"
)

func validProfileJSON() string {
	return `{
		"profile_version": "1.0",
		"image_digest": "sha256:` + strings.Repeat("a", 64) + `",
		"generated_by": "learning_mode",
		"approved_by": "operator:neal",
		"parallel_safe": false,
		"tools": [{
			"name": "query_metrics",
			"resource_extractor": { "arg": "database", "type": "resource_id" },
			"effects": ["read"],
			"syscalls": ["read", "write", "openat", "connect", "socket"],
			"filesystem": { "read": ["/app", "/etc/ssl"], "write": ["/tmp/scratch"] },
			"network": [{ "host": "db.internal", "port": 5432, "proto": "tcp" }],
			"max_duration_ms": 5000
		}]
	}`
}

func TestParse_Valid(t *testing.T) {
	p, err := Parse(strings.NewReader(validProfileJSON()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Tools) != 1 || p.Tools[0].Name != "query_metrics" {
		t.Fatalf("unexpected tools: %+v", p.Tools)
	}
	tool, ok := p.ToolByName("query_metrics")
	if !ok || tool.MaxDurationMS != 5000 {
		t.Fatalf("ToolByName lookup failed: %+v ok=%v", tool, ok)
	}
	if _, ok := p.ToolByName("nope"); ok {
		t.Fatalf("expected no match for unknown tool")
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"parallel_safe": false,`, `"parallel_safe": false, "totally_new_field": true,`, 1)
	if _, err := Parse(strings.NewReader(body)); err == nil {
		t.Fatalf("expected error for unknown field, got nil")
	}
}

func TestValidate_RequiresApprover(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"approved_by": "operator:neal",`, `"approved_by": "",`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "approved_by") {
		t.Fatalf("expected approved_by validation error, got %v", err)
	}
}

func TestValidate_RejectsUnsupportedVersion(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"profile_version": "1.0",`, `"profile_version": "99.0",`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "profile_version") {
		t.Fatalf("expected profile_version validation error, got %v", err)
	}
}

func TestValidate_RejectsMalformedDigest(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"sha256:`+strings.Repeat("a", 64)+`"`, `"not-a-digest"`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "image_digest") {
		t.Fatalf("expected image_digest validation error, got %v", err)
	}
}

func TestValidate_RejectsEmptyToolList(t *testing.T) {
	body := `{
		"profile_version": "1.0",
		"image_digest": "sha256:` + strings.Repeat("a", 64) + `",
		"generated_by": "learning_mode",
		"approved_by": "operator:neal",
		"parallel_safe": false,
		"tools": []
	}`
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "no tools") {
		t.Fatalf("expected empty-tools validation error, got %v", err)
	}
}

func TestValidate_RejectsRelativeFilesystemPaths(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"read": ["/app", "/etc/ssl"]`, `"read": ["relative/path"]`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected absolute-path validation error, got %v", err)
	}
}

func TestValidate_RejectsPathTraversal(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"read": ["/app", "/etc/ssl"]`, `"read": ["/app/../etc/shadow"]`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("expected path-traversal validation error, got %v", err)
	}
}

func TestValidate_RejectsBadPort(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"port": 5432`, `"port": 70000`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("expected port validation error, got %v", err)
	}
}

func TestValidate_RejectsUnsupportedProto(t *testing.T) {
	body := strings.Replace(validProfileJSON(), `"proto": "tcp"`, `"proto": "icmp"`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "unsupported proto") {
		t.Fatalf("expected proto validation error, got %v", err)
	}
}

func TestValidate_RejectsDuplicateToolNames(t *testing.T) {
	// Splice a second, duplicate-named tool into the tools array.
	body := strings.Replace(validProfileJSON(), `}]
	}`, `},{
			"name": "query_metrics",
			"resource_extractor": { "arg": "database", "type": "resource_id" },
			"effects": ["read"],
			"syscalls": ["read"],
			"filesystem": { "read": [], "write": [] },
			"network": [],
			"max_duration_ms": 1000
		}]
	}`, 1)
	_, err := Parse(strings.NewReader(body))
	if err == nil || !strings.Contains(err.Error(), "duplicate tool name") {
		t.Fatalf("expected duplicate tool name validation error, got %v", err)
	}
}
