package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// callCtx executes the tool with an explicit context.
func callCtx(t *testing.T, tool *StartTool, ctx context.Context, params string) *mcp.ToolResult {
	t.Helper()
	result, err := tool.Execute(ctx, json.RawMessage(params))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result
}

func TestStartTaskFormWithTasksExtension(t *testing.T) {
	engine := &mockEngine{}
	tool := NewStart(engine)
	ctx := mcp.WithTasksExtension(context.Background())

	result := callCtx(t, tool, ctx, `{"id":"wf-123","steps":[{"tool":"nmap_port_scan"}]}`)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}

	// The async path must be taken, with the exact params passed through.
	if engine.startAsyncParams == nil {
		t.Fatal("tasks-capable campaign_start must delegate to StartAsyncFromJSON")
	}
	if engine.runParams != nil {
		t.Fatal("tasks-capable campaign_start must not run synchronously")
	}

	// The task id must be unmissable: first line of the result.
	text := result.Content[0].Text
	firstLine := text[:strings.IndexByte(text, '\n')]
	if firstLine != "Task wf-123 started — poll with campaign_status or tasks/get." {
		t.Fatalf("first line = %q", firstLine)
	}
	if !strings.Contains(text, "tasks/get") || !strings.Contains(text, "campaign_resume") {
		t.Fatalf("guidance should mention polling and resuming:\n%s", text)
	}

	// Machine clients get the CreateTaskResult shape in structuredContent.
	if result.StructuredContent == nil {
		t.Fatal("task form must carry structuredContent")
	}
	var structured mcp.CreateTaskResult
	if err := json.Unmarshal(result.StructuredContent, &structured); err != nil {
		t.Fatal(err)
	}
	if structured.ResultType != mcp.ResultTypeTask || structured.Task.TaskID != "wf-123" ||
		structured.Task.Status != mcp.TaskStatusWorking || structured.Task.TTLMs != mcp.TaskTTLMS {
		t.Fatalf("structuredContent = %+v", structured)
	}
}

func TestStartTaskFormAlreadyRunning(t *testing.T) {
	engine := &mockEngine{alreadyRunning: true}
	tool := NewStart(engine)
	ctx := mcp.WithTasksExtension(context.Background())

	result := callCtx(t, tool, ctx, `{"id":"wf-123","steps":[{"tool":"nmap_port_scan"}]}`)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	firstLine := text[:strings.IndexByte(text, '\n')]
	if firstLine != "Task wf-123 is already running — poll with campaign_status or tasks/get." {
		t.Fatalf("first line = %q", firstLine)
	}
}

func TestStartSyncWithoutTasksExtension(t *testing.T) {
	engine := &mockEngine{}
	tool := NewStart(engine)

	result := callCtx(t, tool, context.Background(), `{"id":"wf-123","steps":[{"tool":"nmap_port_scan"}]}`)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	if engine.runParams == nil {
		t.Fatal("capability-less campaign_start must run synchronously")
	}
	if engine.startAsyncParams != nil {
		t.Fatal("capability-less campaign_start must not take the async path")
	}
	if result.StructuredContent != nil {
		t.Fatal("sync result must not carry a task structuredContent")
	}
}

func TestStartTaskFormEngineError(t *testing.T) {
	engine := &mockEngine{runErr: fmt.Errorf("invalid campaign params: unknown field \"staps\"")}
	tool := NewStart(engine)
	ctx := mcp.WithTasksExtension(context.Background())

	result := callCtx(t, tool, ctx, `{"steps":[]}`)
	if !result.IsError {
		t.Fatal("expected error result for engine failure")
	}
	if !strings.Contains(result.Content[0].Text, "campaign failed to start") {
		t.Fatalf("error text should wrap engine error: %s", result.Content[0].Text)
	}
}
