package learning_test

import (
	"context"
	"strings"
	"testing"

	"mcp-warden/sandbox/compile"
	"mcp-warden/sandbox/learning"
	"mcp-warden/sandbox/runtime"
	"mcp-warden/sandbox/runtime/runtimetest"
)

func TestNew_RejectsMissingAcknowledgement(t *testing.T) {
	_, err := learning.New(runtimetest.New(), learning.UnconfinedAcknowledgement{})
	if err == nil {
		t.Fatalf("expected error when constructed without AcknowledgeUnconfinedExecution")
	}
}

func TestNew_AcceptsExplicitAcknowledgement(t *testing.T) {
	sup, err := learning.New(runtimetest.New(), learning.AcknowledgeUnconfinedExecution())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sup == nil {
		t.Fatalf("expected non-nil supervisor")
	}
}

func TestNew_RefusesProductionEnvironment(t *testing.T) {
	t.Setenv("MCP_WARDEN_ENV", "production")
	_, err := learning.New(runtimetest.New(), learning.AcknowledgeUnconfinedExecution())
	if err == nil || !strings.Contains(err.Error(), "production") {
		t.Fatalf("expected refusal to start in production, got %v", err)
	}
}

func TestNew_AllowsNonProductionEnvironment(t *testing.T) {
	t.Setenv("MCP_WARDEN_ENV", "staging")
	if _, err := learning.New(runtimetest.New(), learning.AcknowledgeUnconfinedExecution()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewContainer_UsesCreateUnconfinedNotCreate(t *testing.T) {
	fake := runtimetest.New()
	sup, err := learning.New(fake, learning.AcknowledgeUnconfinedExecution())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	c, err := sup.NewContainer(context.Background(), &compile.CompiledPolicy{ToolNames: []string{"profiling_target"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.WasCreatedUnconfined(c.ID()) {
		t.Fatalf("expected CreateUnconfined to be called, not Create")
	}
	if fake.WasCreated(c.ID()) {
		t.Fatalf("learning containers must never go through the enforcing Create path")
	}
	if c.State() != learning.StateRunning {
		t.Fatalf("state = %v, want RUNNING", c.State())
	}
}

func TestExecute_RecordIsAlwaysTaggedLearningMode(t *testing.T) {
	fake := runtimetest.New()
	sup, err := learning.New(fake, learning.AcknowledgeUnconfinedExecution())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	c, err := sup.NewContainer(context.Background(), &compile.CompiledPolicy{ToolNames: []string{"profiling_target"}})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	rec, err := sup.Execute(context.Background(), c, runtime.ExecRequest{RequestID: "req_1", ToolName: "profiling_target"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.LearningMode() {
		t.Fatalf("ExecutionRecord.LearningMode() = false, want true — unrepresentable state reached")
	}
}

func TestDestroy_TearsDownContainer(t *testing.T) {
	fake := runtimetest.New()
	sup, err := learning.New(fake, learning.AcknowledgeUnconfinedExecution())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	c, err := sup.NewContainer(context.Background(), &compile.CompiledPolicy{ToolNames: []string{"profiling_target"}})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := sup.Destroy(context.Background(), c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.State() != learning.StateDestroyed {
		t.Fatalf("state = %v, want DESTROYED", c.State())
	}
	if !fake.WasDestroyed(c.ID()) {
		t.Fatalf("Destroy was never called on the backend")
	}
}
