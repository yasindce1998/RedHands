package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PivotInput struct {
	Action    string `json:"action"`
	SessionID string `json:"session_id,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type PivotTool struct {
	exec executor.Executor
}

func NewPivot(exec executor.Executor) *PivotTool {
	return &PivotTool{exec: exec}
}

func (t *PivotTool) Name() string { return "sliver_pivot" }

func (t *PivotTool) Description() string {
	return "Manage Sliver pivot listeners for lateral movement. Create TCP or named-pipe pivots on compromised hosts to relay implant traffic through the network."
}

func (t *PivotTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "start", "stop"],
				"description": "Pivot action"
			},
			"session_id": {
				"type": "string",
				"description": "Session ID to create pivot on"
			},
			"protocol": {
				"type": "string",
				"enum": ["tcp", "named-pipe"],
				"description": "Pivot protocol"
			},
			"port": {
				"type": "integer",
				"description": "Pivot listen port (TCP only)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *PivotTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PivotInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"pivots"}
	case "start":
		if input.SessionID == "" {
			return errorResult("session_id is required for start action"), nil
		}
		if input.Protocol == "" {
			return errorResult("protocol is required for start action"), nil
		}
		args = []string{"pivot", input.Protocol, "-s", input.SessionID}
		if input.Port > 0 {
			args = append(args, "--bind", fmt.Sprintf("0.0.0.0:%d", input.Port))
		}
	case "stop":
		args = []string{"pivots", "--kill-all"}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver pivot failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Sliver Pivot: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No active pivots.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// PortForward tool

type PortFwdInput struct {
	Action    string `json:"action"`
	SessionID string `json:"session_id,omitempty"`
	Remote    string `json:"remote,omitempty"`
	Bind      string `json:"bind,omitempty"`
}

type PortFwdTool struct {
	exec executor.Executor
}

func NewPortFwd(exec executor.Executor) *PortFwdTool {
	return &PortFwdTool{exec: exec}
}

func (t *PortFwdTool) Name() string { return "sliver_portfwd" }

func (t *PortFwdTool) Description() string {
	return "Manage port forwarding through Sliver implants. Forward local ports to remote services accessible from the compromised host."
}

func (t *PortFwdTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "add", "remove"],
				"description": "Port forward action"
			},
			"session_id": {
				"type": "string",
				"description": "Session ID"
			},
			"remote": {
				"type": "string",
				"description": "Remote address (host:port)"
			},
			"bind": {
				"type": "string",
				"description": "Local bind address (host:port)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *PortFwdTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PortFwdInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Remote, "remote"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Bind, "bind"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"portfwd"}
		if input.SessionID != "" {
			args = append(args, "-s", input.SessionID)
		}
	case "add":
		if input.SessionID == "" {
			return errorResult("session_id is required for add action"), nil
		}
		if input.Remote == "" {
			return errorResult("remote is required for add action"), nil
		}
		args = []string{"portfwd", "add", "-s", input.SessionID, "-r", input.Remote}
		if input.Bind != "" {
			args = append(args, "-b", input.Bind)
		}
	case "remove":
		args = []string{"portfwd", "rm", "--kill-all"}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver portfwd failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Sliver Port Forward: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No active port forwards.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
