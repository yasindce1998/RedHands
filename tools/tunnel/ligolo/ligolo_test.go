package ligolo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type mockExecutor struct {
	stdout []byte
	stderr []byte
	err    error
}

func (m *mockExecutor) Run(ctx context.Context, binary string, args ...string) (*executor.Result, error) {
	return &executor.Result{Stdout: m.stdout, Stderr: m.stderr}, m.err
}

// --- TestName ---

func TestName(t *testing.T) {
	exec := &mockExecutor{}
	tests := []struct {
		name     string
		toolName string
		tool     interface{ Name() string }
	}{
		{"ProxyStart", "ligolo_start", NewProxyStart(exec)},
		{"Route", "ligolo_route", NewRoute(exec)},
		{"Listener", "ligolo_listener", NewListener(exec)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tool.Name(); got != tt.toolName {
				t.Errorf("Name() = %q, want %q", got, tt.toolName)
			}
		})
	}
}

// --- TestDescription ---

func TestDescription(t *testing.T) {
	exec := &mockExecutor{}
	tests := []struct {
		name string
		tool interface{ Description() string }
	}{
		{"ProxyStart", NewProxyStart(exec)},
		{"Route", NewRoute(exec)},
		{"Listener", NewListener(exec)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tool.Description(); got == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

// --- TestInputSchema ---

func TestInputSchema(t *testing.T) {
	exec := &mockExecutor{}
	tests := []struct {
		name string
		tool interface{ InputSchema() json.RawMessage }
	}{
		{"ProxyStart", NewProxyStart(exec)},
		{"Route", NewRoute(exec)},
		{"Listener", NewListener(exec)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := tt.tool.InputSchema()
			var parsed map[string]interface{}
			if err := json.Unmarshal(schema, &parsed); err != nil {
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
	ctx := context.Background()

	tests := []struct {
		name   string
		params string
		stdout string
		tool   interface {
			Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
		}
	}{
		{
			"ProxyStart",
			`{}`,
			"proxy started successfully",
			NewProxyStart(&mockExecutor{stdout: []byte("proxy started successfully")}),
		},
		{
			"Route",
			`{"action": "add", "network": "10.0.0.0/24"}`,
			"route added successfully",
			NewRoute(&mockExecutor{stdout: []byte("route added successfully")}),
		},
		{
			"Listener",
			`{"action": "list"}`,
			"listeners listed",
			NewListener(&mockExecutor{stdout: []byte("listeners listed")}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.tool.Execute(ctx, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true, content: %v", result.Content)
			}
			if len(result.Content) == 0 {
				t.Fatal("Execute() returned empty content")
			}
			found := false
			for _, block := range result.Content {
				if block.Type == "text" && strings.Contains(block.Text, tt.stdout) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Execute() content does not contain mock stdout %q", tt.stdout)
			}
		})
	}
}

// --- TestShellInjection ---

func TestShellInjection(t *testing.T) {
	ctx := context.Background()
	exec := &mockExecutor{stdout: []byte("should not reach")}
	tool := NewRoute(exec)

	chars := []struct {
		name string
		char string
	}{
		{"semicolon", ";"},
		{"pipe", "|"},
		{"ampersand", "&"},
		{"backtick", "`"},
		{"dollar", "$"},
	}
	for _, tc := range chars {
		t.Run(tc.name, func(t *testing.T) {
			params := json.RawMessage(`{"action": "add", "network": "10.0.0.0/24` + tc.char + `whoami"}`)
			result, err := tool.Execute(ctx, params)
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatal("Execute() should return IsError=true for shell metacharacter")
			}
			found := false
			for _, block := range result.Content {
				if block.Type == "text" && strings.Contains(block.Text, "contains forbidden character") {
					found = true
					break
				}
			}
			if !found {
				t.Error("Execute() error text should contain \"contains forbidden character\"")
			}
		})
	}
}
