package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ListenersInput struct {
	Action   string `json:"action"`
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type ListenersTool struct {
	exec executor.Executor
}

func NewListeners(exec executor.Executor) *ListenersTool {
	return &ListenersTool{exec: exec}
}

func (t *ListenersTool) Name() string { return "sliver_listeners" }

func (t *ListenersTool) Description() string {
	return "Manage Sliver C2 listeners. Start, stop, or list mTLS, HTTP/S, DNS, and WireGuard listeners for implant callbacks."
}

func (t *ListenersTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["start", "stop", "list"],
				"description": "Listener management action"
			},
			"protocol": {
				"type": "string",
				"enum": ["mtls", "http", "https", "dns", "wg"],
				"description": "Listener protocol"
			},
			"host": {
				"type": "string",
				"description": "Listen host/interface"
			},
			"port": {
				"type": "integer",
				"description": "Listen port"
			},
			"domain": {
				"type": "string",
				"description": "Domain for DNS/HTTP listeners"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ListenersTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ListenersInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Host, "host"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"jobs"}
	case "start":
		if input.Protocol == "" {
			return errorResult("protocol is required for start action"), nil
		}
		args = []string{input.Protocol}
		if input.Host != "" {
			args = append(args, "--lhost", input.Host)
		}
		if input.Port > 0 {
			args = append(args, "--lport", fmt.Sprintf("%d", input.Port))
		}
		if input.Domain != "" {
			args = append(args, "--domain", input.Domain)
		}
	case "stop":
		args = []string{"jobs", "--kill-all"}
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver listeners failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Sliver Listeners: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No active listeners.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
