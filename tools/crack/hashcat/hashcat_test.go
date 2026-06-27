package hashcat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestName(t *testing.T) {
	mock := executor.NewMock()

	tests := []struct {
		name     string
		expected string
	}{
		{"Crack", "hashcat_crack"},
		{"Benchmark", "hashcat_benchmark"},
		{"Show", "hashcat_show"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			switch tt.name {
			case "Crack":
				got = NewCrack(mock).Name()
			case "Benchmark":
				got = NewBenchmark(mock).Name()
			case "Show":
				got = NewShow(mock).Name()
			}
			if got != tt.expected {
				t.Errorf("Name() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	mock := executor.NewMock()

	tests := []struct {
		name string
	}{
		{"Crack"},
		{"Benchmark"},
		{"Show"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var desc string
			switch tt.name {
			case "Crack":
				desc = NewCrack(mock).Description()
			case "Benchmark":
				desc = NewBenchmark(mock).Description()
			case "Show":
				desc = NewShow(mock).Description()
			}
			if desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()

	tests := []struct {
		name string
	}{
		{"Crack"},
		{"Benchmark"},
		{"Show"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var schema json.RawMessage
			switch tt.name {
			case "Crack":
				schema = NewCrack(mock).InputSchema()
			case "Benchmark":
				schema = NewBenchmark(mock).InputSchema()
			case "Show":
				schema = NewShow(mock).InputSchema()
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(schema, &parsed); err != nil {
				t.Fatalf("InputSchema() returned invalid JSON: %v", err)
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

func TestExecute(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		params string
		stdout string
	}{
		{
			name:   "Crack",
			params: `{"hash_file": "/tmp/hashes.txt", "hash_type": 1000}`,
			stdout: "Session..........: hashcat\nStatus...........: Cracked",
		},
		{
			name:   "Benchmark",
			params: `{}`,
			stdout: "Hashmode: 0 - MD5\nSpeed.#1.........:  5000.0 MH/s",
		},
		{
			name:   "Show",
			params: `{"hash_file": "/tmp/hashes.txt", "hash_type": 1000}`,
			stdout: "hash1:password123\nhash2:admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(tt.stdout)
			}

			var result *mcp.ToolResult
			var err error

			switch tt.name {
			case "Crack":
				result, err = NewCrack(mock).Execute(ctx, json.RawMessage(tt.params))
			case "Benchmark":
				result, err = NewBenchmark(mock).Execute(ctx, json.RawMessage(tt.params))
			case "Show":
				result, err = NewShow(mock).Execute(ctx, json.RawMessage(tt.params))
			}

			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Errorf("Execute() returned IsError=true, expected success")
			}
			if len(result.Content) == 0 {
				t.Fatal("Execute() returned empty content")
			}
			if !strings.Contains(result.Content[0].Text, tt.stdout) {
				t.Errorf("Execute() content does not contain expected stdout text %q", tt.stdout)
			}
		})
	}
}

func TestShellInjection(t *testing.T) {
	ctx := context.Background()

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

	for _, tt := range chars {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("should not run")
			}
			tool := NewCrack(mock)
			params := json.RawMessage(`{"hash_file": "/tmp/hashes` + tt.char + `evil.txt", "hash_type": 1000}`)

			result, err := tool.Execute(ctx, params)
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Errorf("Execute() with %q in hash_file did not return IsError=true", tt.char)
			}
			if !strings.Contains(result.Content[0].Text, "contains forbidden character") {
				t.Errorf("Execute() error text does not contain 'contains forbidden character', got: %s", result.Content[0].Text)
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}
