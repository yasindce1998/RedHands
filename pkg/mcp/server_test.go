package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type mockTool struct{}

func (m *mockTool) Name() string        { return "test_tool" }
func (m *mockTool) Description() string  { return "A test tool" }
func (m *mockTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}`)
}
func (m *mockTool) Execute(_ context.Context, params json.RawMessage) (*ToolResult, error) {
	var input struct {
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return &ToolResult{
		Content: []ContentBlock{{Type: "text", Text: "echo: " + input.Msg}},
	}, nil
}

func TestInitializeHandshake(t *testing.T) {
	srv := NewServer("test-server", "1.0.0")
	srv.RegisterTool(&mockTool{})

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}` + "\n"
	input += `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"

	var out bytes.Buffer
	err := srv.serve(context.Background(), strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("serve error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 1 {
		t.Fatal("expected at least 1 response line")
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var initResult InitializeResult
	if err := json.Unmarshal(resultBytes, &initResult); err != nil {
		t.Fatalf("unmarshalling init result: %v", err)
	}

	if initResult.ServerInfo.Name != "test-server" {
		t.Errorf("expected server name test-server, got %s", initResult.ServerInfo.Name)
	}
	if initResult.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got %s", initResult.ProtocolVersion)
	}
}

func TestToolsList(t *testing.T) {
	srv := NewServer("test-server", "1.0.0")
	srv.RegisterTool(&mockTool{})

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"

	var out bytes.Buffer
	if err := srv.serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var toolsList ToolsListResult
	if err := json.Unmarshal(resultBytes, &toolsList); err != nil {
		t.Fatalf("unmarshalling tools list: %v", err)
	}

	if len(toolsList.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(toolsList.Tools))
	}
	if toolsList.Tools[0].Name != "test_tool" {
		t.Errorf("expected tool name test_tool, got %s", toolsList.Tools[0].Name)
	}
}

func TestToolsCall(t *testing.T) {
	srv := NewServer("test-server", "1.0.0")
	srv.RegisterTool(&mockTool{})

	input := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"test_tool","arguments":{"msg":"hello"}}}` + "\n"

	var out bytes.Buffer
	if err := srv.serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	resultBytes, _ := json.Marshal(resp.Result)
	var toolResult ToolResult
	if err := json.Unmarshal(resultBytes, &toolResult); err != nil {
		t.Fatalf("unmarshalling tool result: %v", err)
	}

	if len(toolResult.Content) != 1 || toolResult.Content[0].Text != "echo: hello" {
		t.Errorf("unexpected result: %+v", toolResult)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv := NewServer("test-server", "1.0.0")

	input := `{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}` + "\n"

	var out bytes.Buffer
	if err := srv.serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", ErrCodeMethodNotFound, resp.Error.Code)
	}
}

func TestUnknownTool(t *testing.T) {
	srv := NewServer("test-server", "1.0.0")

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nonexistent"}}` + "\n"

	var out bytes.Buffer
	if err := srv.serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("serve error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("parsing response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error response")
	}
}
