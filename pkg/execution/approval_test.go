package execution

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// recordingAuditLogger captures audit events in memory.
type recordingAuditLogger struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (l *recordingAuditLogger) Log(_ context.Context, event audit.AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *recordingAuditLogger) Close() error { return nil }

func (l *recordingAuditLogger) snapshot() []audit.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.AuditEvent(nil), l.events...)
}

// approvedTool is a tool whose policy requires approval; execTool records
// whether it executed.
type approvalTestTool struct {
	name string
	ran  int
}

func (t *approvalTestTool) Name() string        { return t.name }
func (t *approvalTestTool) Description() string { return "test" }
func (t *approvalTestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}

func (t *approvalTestTool) Execute(_ context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	t.ran++
	return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "ran"}}}, nil
}

func newApprovalTestServer(t *testing.T) (*mcp.Server, *approvalTestTool, *recordingAuditLogger) {
	t.Helper()
	srv := mcp.NewServer("test", "1")
	tool := &approvalTestTool{name: "dangerous"}
	if err := srv.RegisterTool(tool); err != nil {
		t.Fatal(err)
	}
	logger := &recordingAuditLogger{}
	srv.Use(ApprovalWithAudit(nil, logger))
	return srv, tool, logger
}

func TestApprovalMRTRInputRequired(t *testing.T) {
	srv, tool, logger := newApprovalTestServer(t)

	result, err := srv.ExecuteTool(mcp.WithTasksExtension(context.Background()), "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("input_required must not be an error result: %+v", result)
	}
	if result.ResultType != mcp.ResultTypeInputRequired {
		t.Fatalf("resultType = %q", result.ResultType)
	}
	req, ok := result.InputRequests[mcp.ApprovalInputKey]
	if !ok {
		t.Fatalf("inputRequests = %v", result.InputRequests)
	}
	if req.Type != mcp.InputRequestTypeElicitation || req.RequestID == "" || !strings.Contains(req.Message, "dangerous") {
		t.Fatalf("inputRequest = %+v", req)
	}
	if tool.ran != 0 {
		t.Fatal("gated tool must not execute on input_required")
	}
	if events := logger.snapshot(); len(events) != 0 {
		t.Fatalf("no bypass may be audited before approval: %v", events)
	}
}

func TestApprovalMRTRBypassPerCall(t *testing.T) {
	srv, tool, logger := newApprovalTestServer(t)

	// Re-issued call with an affirmative response executes once and is
	// audited as an approval bypass.
	ctx := mcp.WithTasksExtension(mcp.WithInputResponses(context.Background(), map[string]json.RawMessage{
		mcp.ApprovalInputKey: json.RawMessage(`{"approved":true}`),
	}))
	result, err := srv.ExecuteTool(ctx, "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.ResultType != "" {
		t.Fatalf("approved call must execute normally: %+v", result)
	}
	if tool.ran != 1 {
		t.Fatalf("approved call must execute exactly once, ran %d", tool.ran)
	}
	events := logger.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected one approval/bypass audit event, got %v", events)
	}
	if events[0].Action != "approval/bypass" || events[0].Tool != "dangerous" || events[0].Result != "approved via elicitation" {
		t.Fatalf("bypass audit event = %+v", events[0])
	}

	// The bypass is per-call: the next call without a response trips again.
	result, err = srv.ExecuteTool(mcp.WithTasksExtension(context.Background()), "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.ResultType != mcp.ResultTypeInputRequired || tool.ran != 1 {
		t.Fatalf("bypass must not persist across calls: %+v ran=%d", result, tool.ran)
	}
	if events := logger.snapshot(); len(events) != 1 {
		t.Fatalf("no additional bypass may be audited: %v", events)
	}
}

func TestApprovalMRTRExplicitDenial(t *testing.T) {
	srv, tool, logger := newApprovalTestServer(t)
	ctx := mcp.WithTasksExtension(mcp.WithInputResponses(context.Background(), map[string]json.RawMessage{
		mcp.ApprovalInputKey: json.RawMessage(`{"approved":false}`),
	}))
	result, err := srv.ExecuteTool(ctx, "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "denied") {
		t.Fatalf("explicit denial must fail: %+v", result)
	}
	if tool.ran != 0 {
		t.Fatal("denied tool must not execute")
	}
	if events := logger.snapshot(); len(events) != 0 {
		t.Fatalf("denial must not be audited as a bypass: %v", events)
	}
}

func TestApprovalMRTRResponsesWithoutCapabilityIgnored(t *testing.T) {
	srv, tool, _ := newApprovalTestServer(t)
	// inputResponses on a capability-less request must never grant a
	// bypass: fail closed exactly as before.
	ctx := mcp.WithInputResponses(context.Background(), map[string]json.RawMessage{
		mcp.ApprovalInputKey: json.RawMessage(`{"approved":true}`),
	})
	result, err := srv.ExecuteTool(ctx, "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "requires operator approval") {
		t.Fatalf("capability-less request must fail closed: %+v", result)
	}
	if tool.ran != 0 {
		t.Fatal("tool must not execute")
	}
}

func TestApprovalMiddlewareStillHonorsApprovedList(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	tool := &approvalTestTool{name: "dangerous"}
	if err := srv.RegisterTool(tool); err != nil {
		t.Fatal(err)
	}
	srv.Use(Approval([]string{"dangerous"}))
	result, err := srv.ExecuteTool(mcp.WithTasksExtension(context.Background()), "dangerous", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.ResultType != "" || tool.ran != 1 {
		t.Fatalf("approved tool must execute without elicitation: %+v ran=%d", result, tool.ran)
	}
}

// TestApprovalAuditDisabledWithoutLogger: Approval(nil logger) must not
// panic on bypass.
func TestApprovalAuditDisabledWithoutLogger(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	tool := &approvalTestTool{name: "dangerous"}
	if err := srv.RegisterTool(tool); err != nil {
		t.Fatal(err)
	}
	srv.Use(Approval(nil))
	ctx := mcp.WithTasksExtension(mcp.WithInputResponses(context.Background(), map[string]json.RawMessage{
		mcp.ApprovalInputKey: json.RawMessage(`{"approved":true}`),
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, err := srv.ExecuteTool(ctx, "dangerous", json.RawMessage(`{}`))
		if err != nil || result.IsError || tool.ran != 1 {
			t.Errorf("bypass without audit logger: %+v %v ran=%d", result, err, tool.ran)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bypass without audit logger hung")
	}
}
