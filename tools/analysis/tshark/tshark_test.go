package tshark

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

func allTools(exec executor.Executor) []struct {
	name string
	tool mcp.Tool
} {
	return []struct {
		name string
		tool mcp.Tool
	}{
		{"Capture", NewCapture(exec)},
		{"Read", NewRead(exec)},
		{"Stats", NewStats(exec)},
		{"Extract", NewExtract(exec)},
		{"Follow", NewFollow(exec)},
	}
}

func TestName(t *testing.T) {
	mock := executor.NewMock()
	tests := []struct {
		name     string
		tool     mcp.Tool
		expected string
	}{
		{"Capture", NewCapture(mock), "tshark_capture"},
		{"Read", NewRead(mock), "tshark_read"},
		{"Stats", NewStats(mock), "tshark_stats"},
		{"Extract", NewExtract(mock), "tshark_extract"},
		{"Follow", NewFollow(mock), "tshark_follow"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tool.Name(); got != tc.expected {
				t.Errorf("Name() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	for _, tc := range allTools(mock) {
		t.Run(tc.name, func(t *testing.T) {
			if desc := tc.tool.Description(); desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	for _, tc := range allTools(mock) {
		t.Run(tc.name, func(t *testing.T) {
			schema := tc.tool.InputSchema()
			var m map[string]any
			if err := json.Unmarshal(schema, &m); err != nil {
				t.Fatalf("InputSchema() is not valid JSON: %v", err)
			}
			if m["type"] != "object" {
				t.Errorf("InputSchema() type = %v, want \"object\"", m["type"])
			}
			if _, ok := m["properties"]; !ok {
				t.Error("InputSchema() missing \"properties\" key")
			}
		})
	}
}

func TestExecute(t *testing.T) {
	const mockOutput = "sample tshark output\npacket data here"

	tests := []struct {
		name   string
		tool   func(executor.Executor) mcp.Tool
		params map[string]any
	}{
		{
			name:   "Capture",
			tool:   func(e executor.Executor) mcp.Tool { return NewCapture(e) },
			params: map[string]any{"interface": "eth0"},
		},
		{
			name:   "Read",
			tool:   func(e executor.Executor) mcp.Tool { return NewRead(e) },
			params: map[string]any{"file": "/tmp/capture.pcap"},
		},
		{
			name:   "Stats",
			tool:   func(e executor.Executor) mcp.Tool { return NewStats(e) },
			params: map[string]any{"file": "/tmp/capture.pcap", "type": "io"},
		},
		{
			name:   "Extract",
			tool:   func(e executor.Executor) mcp.Tool { return NewExtract(e) },
			params: map[string]any{"file": "/tmp/capture.pcap", "fields": "ip.src,ip.dst"},
		},
		{
			name:   "Follow",
			tool:   func(e executor.Executor) mcp.Tool { return NewFollow(e) },
			params: map[string]any{"file": "/tmp/capture.pcap", "protocol": "tcp", "stream": 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(mockOutput)
			}
			tool := tc.tool(mock)

			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %v", result.Content)
			}

			found := false
			for _, block := range result.Content {
				if block.Type == "text" && strings.Contains(block.Text, "sample tshark output") {
					found = true
					break
				}
			}
			if !found {
				t.Error("Execute() result does not contain expected mock stdout text")
			}
		})
	}
}

func TestShellInjection(t *testing.T) {
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
			mock := executor.NewMock()
			tool := NewCapture(mock)

			params := map[string]any{
				"interface": "eth0" + tc.char + "malicious",
			}
			result, err := tool.Execute(context.Background(), mustJSON(params))
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
				t.Errorf("error text should contain \"contains forbidden character\", got: %v", result.Content)
			}

			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}
