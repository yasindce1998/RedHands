package john

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

func TestName(t *testing.T) {
	mock := executor.NewMock()
	tests := []struct {
		name     string
		toolName string
		expected string
	}{
		{"Crack", NewCrack(mock).Name(), "john_crack"},
		{"Show", NewShow(mock).Name(), "john_show"},
		{"Formats", NewFormats(mock).Name(), "john_formats"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.toolName != tt.expected {
				t.Errorf("Name() = %q, want %q", tt.toolName, tt.expected)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	tests := []struct {
		name string
		desc string
	}{
		{"Crack", NewCrack(mock).Description()},
		{"Show", NewShow(mock).Description()},
		{"Formats", NewFormats(mock).Description()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	tests := []struct {
		name   string
		schema json.RawMessage
	}{
		{"Crack", NewCrack(mock).InputSchema()},
		{"Show", NewShow(mock).InputSchema()},
		{"Formats", NewFormats(mock).InputSchema()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parsed map[string]interface{}
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

func TestExecute(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		params string
		run    func(*executor.MockExecutor, string) error
	}{
		{
			name:   "Crack",
			stdout: "Loaded 5 password hashes",
			params: `{"hash_file": "/tmp/hashes.txt"}`,
			run: func(mock *executor.MockExecutor, params string) error {
				tool := NewCrack(mock)
				result, err := tool.Execute(context.Background(), json.RawMessage(params))
				if err != nil {
					return err
				}
				if result.IsError {
					t.Errorf("Crack: Execute() returned IsError=true")
				}
				found := false
				for _, block := range result.Content {
					if block.Type == "text" && strings.Contains(block.Text, "Loaded 5 password hashes") {
						found = true
					}
				}
				if !found {
					t.Errorf("Crack: result does not contain expected stdout")
				}
				return nil
			},
		},
		{
			name:   "Show",
			stdout: "admin:password123",
			params: `{"hash_file": "/tmp/hashes.txt"}`,
			run: func(mock *executor.MockExecutor, params string) error {
				tool := NewShow(mock)
				result, err := tool.Execute(context.Background(), json.RawMessage(params))
				if err != nil {
					return err
				}
				if result.IsError {
					t.Errorf("Show: Execute() returned IsError=true")
				}
				found := false
				for _, block := range result.Content {
					if block.Type == "text" && strings.Contains(block.Text, "admin:password123") {
						found = true
					}
				}
				if !found {
					t.Errorf("Show: result does not contain expected stdout")
				}
				return nil
			},
		},
		{
			name:   "Formats",
			stdout: "descrypt, bsdicrypt, md5crypt",
			params: `{}`,
			run: func(mock *executor.MockExecutor, params string) error {
				tool := NewFormats(mock)
				result, err := tool.Execute(context.Background(), json.RawMessage(params))
				if err != nil {
					return err
				}
				if result.IsError {
					t.Errorf("Formats: Execute() returned IsError=true")
				}
				found := false
				for _, block := range result.Content {
					if block.Type == "text" && strings.Contains(block.Text, "descrypt, bsdicrypt, md5crypt") {
						found = true
					}
				}
				if !found {
					t.Errorf("Formats: result does not contain expected stdout")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(tt.stdout)
			}
			if err := tt.run(mock, tt.params); err != nil {
				t.Fatalf("Execute() returned error: %v", err)
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
	for _, c := range chars {
		t.Run(c.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("should not run")
			}
			tool := NewCrack(mock)

			params := json.RawMessage(`{"hash_file": "/tmp/hashes` + c.char + `evil.txt"}`)
			result, err := tool.Execute(context.Background(), params)
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
				}
			}
			if !found {
				t.Error("error text should contain \"contains forbidden character\"")
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called for invalid input")
			}
		})
	}
}
