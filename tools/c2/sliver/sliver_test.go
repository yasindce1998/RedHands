package sliver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// toolAdapter wraps the Execute method shared by all sliver tools.
type toolAdapter struct {
	name        string
	description string
	schema      json.RawMessage
	execute     func(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
}

func allTools(m *executor.MockExecutor) []toolAdapter {
	gen := NewGenerate(m)
	lis := NewListeners(m)
	ses := NewSessions(m)
	bea := NewBeacons(m)
	exe := NewExecute(m)
	upl := NewUpload(m)
	dwn := NewDownload(m)
	pvt := NewPivot(m)
	pfw := NewPortFwd(m)

	return []toolAdapter{
		{gen.Name(), gen.Description(), gen.InputSchema(), gen.Execute},
		{lis.Name(), lis.Description(), lis.InputSchema(), lis.Execute},
		{ses.Name(), ses.Description(), ses.InputSchema(), ses.Execute},
		{bea.Name(), bea.Description(), bea.InputSchema(), bea.Execute},
		{exe.Name(), exe.Description(), exe.InputSchema(), exe.Execute},
		{upl.Name(), upl.Description(), upl.InputSchema(), upl.Execute},
		{dwn.Name(), dwn.Description(), dwn.InputSchema(), dwn.Execute},
		{pvt.Name(), pvt.Description(), pvt.InputSchema(), pvt.Execute},
		{pfw.Name(), pfw.Description(), pfw.InputSchema(), pfw.Execute},
	}
}

// --- TestName ---

func TestName(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	expected := []string{
		"sliver_generate",
		"sliver_listeners",
		"sliver_sessions",
		"sliver_beacons",
		"sliver_execute",
		"sliver_upload",
		"sliver_download",
		"sliver_pivot",
		"sliver_portfwd",
	}

	for i, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != expected[i] {
				t.Errorf("Name() = %q, want %q", tt.name, expected[i])
			}
		})
	}
}

// --- TestDescription ---

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			if tt.description == "" {
				t.Error("Description() should not be empty")
			}
		})
	}
}

// --- TestInputSchema ---

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			var parsed map[string]any
			if err := json.Unmarshal(tt.schema, &parsed); err != nil {
				t.Fatalf("InputSchema() is not valid JSON: %v", err)
			}
			if parsed["type"] != "object" {
				t.Errorf("InputSchema() type = %v, want \"object\"", parsed["type"])
			}
			if _, ok := parsed["properties"]; !ok {
				t.Error("InputSchema() missing \"properties\" key")
			}
		})
	}
}

// --- TestExecute ---

func TestExecute(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		newFn  func(*executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error)
	}{
		{
			name:   "Generate",
			params: map[string]any{"os": "linux"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewGenerate(m).Execute
			},
		},
		{
			name:   "Listeners",
			params: map[string]any{"action": "list"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewListeners(m).Execute
			},
		},
		{
			name:   "Sessions",
			params: map[string]any{"action": "list"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewSessions(m).Execute
			},
		},
		{
			name:   "Beacons",
			params: map[string]any{"action": "list"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewBeacons(m).Execute
			},
		},
		{
			name:   "Execute",
			params: map[string]any{"session_id": "abc123", "command": "whoami"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewExecute(m).Execute
			},
		},
		{
			name:   "Upload",
			params: map[string]any{"session_id": "abc123", "local_path": "/tmp/file.txt", "remote_path": "/tmp/dest.txt"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewUpload(m).Execute
			},
		},
		{
			name:   "Download",
			params: map[string]any{"session_id": "abc123", "remote_path": "/tmp/file.txt"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewDownload(m).Execute
			},
		},
		{
			name:   "Pivot",
			params: map[string]any{"action": "list"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewPivot(m).Execute
			},
		},
		{
			name:   "PortFwd",
			params: map[string]any{"action": "list"},
			newFn: func(m *executor.MockExecutor) func(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
				return NewPortFwd(m).Execute
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("mock output for " + tt.name)
			}
			executeFn := tt.newFn(mock)

			result, err := executeFn(context.Background(), mustJSON(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true, content: %s", result.Content[0].Text)
			}
			if len(result.Content) == 0 {
				t.Fatal("Execute() returned empty content")
			}
			if !strings.Contains(result.Content[0].Text, "mock output for "+tt.name) {
				t.Errorf("Execute() content does not contain mock stdout, got: %s", result.Content[0].Text)
			}
		})
	}
}

// --- TestShellInjection ---

func TestShellInjection(t *testing.T) {
	metachars := []struct {
		name string
		char string
	}{
		{"semicolon", ";"},
		{"pipe", "|"},
		{"ampersand", "&"},
		{"backtick", "`"},
		{"dollar", "$"},
	}

	for _, mc := range metachars {
		t.Run(mc.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewGenerate(mock)

			// Inject metachar into the first required field ("os")
			params := map[string]any{"os": "linux" + mc.char + "id"}
			result, err := tool.Execute(context.Background(), mustJSON(params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Error("expected IsError=true for shell metachar in input")
			}
			if len(result.Content) == 0 {
				t.Fatal("expected error content")
			}
			if !strings.Contains(result.Content[0].Text, "contains forbidden character") {
				t.Errorf("error text should contain 'contains forbidden character', got: %s", result.Content[0].Text)
			}
		})
	}
}
