package chisel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ServerInput struct {
	Port    int    `json:"port,omitempty"`
	Host    string `json:"host,omitempty"`
	Auth    string `json:"auth,omitempty"`
	Reverse bool   `json:"reverse,omitempty"`
	Socks5  bool   `json:"socks5,omitempty"`
	Key     string `json:"key,omitempty"`
}

type ServerTool struct {
	exec executor.Executor
}

func NewServer(exec executor.Executor) *ServerTool {
	return &ServerTool{exec: exec}
}

func (t *ServerTool) Name() string { return "chisel_server" }

func (t *ServerTool) Description() string {
	return "Start a Chisel server for tunneling connections. Supports forward/reverse tunnels, SOCKS5 proxy, and authenticated connections over HTTP/WebSocket."
}

func (t *ServerTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"port": {
				"type": "integer",
				"description": "Listen port (default: 8080)"
			},
			"host": {
				"type": "string",
				"description": "Listen host/interface"
			},
			"auth": {
				"type": "string",
				"description": "Authentication credentials (user:pass)"
			},
			"reverse": {
				"type": "boolean",
				"description": "Allow reverse port forwarding"
			},
			"socks5": {
				"type": "boolean",
				"description": "Allow SOCKS5 connections"
			},
			"key": {
				"type": "string",
				"description": "Path to PEM-encoded TLS key"
			}
		}
	}`)
}

func (t *ServerTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ServerInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Host, "host"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Auth, "auth"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Key, "key"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"server"}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Host != "" {
		args = append(args, "--host", input.Host)
	}
	if input.Auth != "" {
		args = append(args, "--auth", input.Auth)
	}
	if input.Reverse {
		args = append(args, "--reverse")
	}
	if input.Socks5 {
		args = append(args, "--socks5")
	}
	if input.Key != "" {
		args = append(args, "--key", input.Key)
	}

	result, err := t.exec.Run(ctx, "chisel", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("chisel server failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Chisel Server\n\n")
	if input.Port > 0 {
		fmt.Fprintf(&sb, "**Port**: %d\n\n", input.Port)
	}
	if output == "" {
		sb.WriteString("Server started.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
