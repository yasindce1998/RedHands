package chisel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ClientInput struct {
	Server  string   `json:"server"`
	Remotes []string `json:"remotes"`
	Auth    string   `json:"auth,omitempty"`
	Socks5  bool     `json:"socks5,omitempty"`
}

type ClientTool struct {
	exec executor.Executor
}

func NewClient(exec executor.Executor) *ClientTool {
	return &ClientTool{exec: exec}
}

func (t *ClientTool) Name() string { return "chisel_client" }

func (t *ClientTool) Description() string {
	return "Connect a Chisel client to a server for tunnel creation. Supports forward tunnels, reverse tunnels, and SOCKS5 proxy with format local:remote or R:remote:local."
}

func (t *ClientTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"server": {
				"type": "string",
				"description": "Server URL (e.g., http://attacker:8080)"
			},
			"remotes": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Tunnel definitions (e.g., '9090:socks', 'R:0.0.0.0:4444:127.0.0.1:4444')"
			},
			"auth": {
				"type": "string",
				"description": "Authentication credentials (user:pass)"
			},
			"socks5": {
				"type": "boolean",
				"description": "Create SOCKS5 tunnel"
			}
		},
		"required": ["server", "remotes"]
	}`)
}

func (t *ClientTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ClientInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.Server, "server"); err != nil {
		return errorResult(err.Error()), nil
	}
	if len(input.Remotes) == 0 {
		return errorResult("remotes is required (at least one tunnel definition)"), nil
	}
	if err := validateSafeString(input.Auth, "auth"); err != nil {
		return errorResult(err.Error()), nil
	}
	for i, r := range input.Remotes {
		if err := validateSafeString(r, fmt.Sprintf("remotes[%d]", i)); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"client", input.Server}
	if input.Auth != "" {
		args = append(args, "--auth", input.Auth)
	}
	args = append(args, input.Remotes...)

	result, err := t.exec.Run(ctx, "chisel", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("chisel client failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Chisel Client\n\n")
	fmt.Fprintf(&sb, "**Server**: %s\n", input.Server)
	fmt.Fprintf(&sb, "**Tunnels**: %s\n\n", strings.Join(input.Remotes, ", "))
	if output == "" {
		sb.WriteString("Client connected.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
