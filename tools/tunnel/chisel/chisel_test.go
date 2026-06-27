package chisel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

type mockExecutor struct {
	stdout []byte
	stderr []byte
	err    error
}

func (m *mockExecutor) Run(ctx context.Context, binary string, args ...string) (*executor.Result, error) {
	return &executor.Result{Stdout: m.stdout, Stderr: m.stderr}, m.err
}

func TestName(t *testing.T) {
	exec := &mockExecutor{}

	t.Run("server", func(t *testing.T) {
		tool := NewServer(exec)
		if tool.Name() != "chisel_server" {
			t.Errorf("expected chisel_server, got %s", tool.Name())
		}
	})

	t.Run("client", func(t *testing.T) {
		tool := NewClient(exec)
		if tool.Name() != "chisel_client" {
			t.Errorf("expected chisel_client, got %s", tool.Name())
		}
	})
}

func TestDescription(t *testing.T) {
	exec := &mockExecutor{}

	t.Run("server", func(t *testing.T) {
		tool := NewServer(exec)
		if tool.Description() == "" {
			t.Error("expected non-empty description")
		}
	})

	t.Run("client", func(t *testing.T) {
		tool := NewClient(exec)
		if tool.Description() == "" {
			t.Error("expected non-empty description")
		}
	})
}

func TestInputSchema(t *testing.T) {
	exec := &mockExecutor{}

	t.Run("server", func(t *testing.T) {
		schema := NewServer(exec).InputSchema()
		var m map[string]interface{}
		if err := json.Unmarshal(schema, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["type"] != "object" {
			t.Errorf("expected type=object, got %v", m["type"])
		}
		if _, ok := m["properties"]; !ok {
			t.Error("expected properties key in schema")
		}
	})

	t.Run("client", func(t *testing.T) {
		schema := NewClient(exec).InputSchema()
		var m map[string]interface{}
		if err := json.Unmarshal(schema, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["type"] != "object" {
			t.Errorf("expected type=object, got %v", m["type"])
		}
		if _, ok := m["properties"]; !ok {
			t.Error("expected properties key in schema")
		}
	})
}

func TestExecute(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		exec := &mockExecutor{
			stdout: []byte("server started on port 8080"),
		}
		tool := NewServer(exec)
		params := json.RawMessage(`{}`)
		result, err := tool.Execute(context.Background(), params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError {
			t.Errorf("expected no error, got error result")
		}
		found := false
		for _, c := range result.Content {
			if strings.Contains(c.Text, "server started on port 8080") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected stdout text in result content")
		}
	})

	t.Run("client", func(t *testing.T) {
		exec := &mockExecutor{
			stdout: []byte("connected to http://10.0.0.1:8080"),
		}
		tool := NewClient(exec)
		params := json.RawMessage(`{"server": "http://10.0.0.1:8080", "remotes": ["9050:socks"]}`)
		result, err := tool.Execute(context.Background(), params)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsError {
			t.Errorf("expected no error, got error result")
		}
		found := false
		for _, c := range result.Content {
			if strings.Contains(c.Text, "connected to http://10.0.0.1:8080") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected stdout text in result content")
		}
	})
}

func TestShellInjection(t *testing.T) {
	exec := &mockExecutor{stdout: []byte("ok")}
	tool := NewClient(exec)

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
			server := "http://evil" + tc.char + "injected"
			params, _ := json.Marshal(map[string]interface{}{
				"server":  server,
				"remotes": []string{"9050:socks"},
			})
			result, err := tool.Execute(context.Background(), json.RawMessage(params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !result.IsError {
				t.Error("expected IsError=true for shell metacharacter")
			}
			found := false
			for _, c := range result.Content {
				if strings.Contains(c.Text, "contains forbidden character") {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected 'contains forbidden character' in error text")
			}
		})
	}
}
