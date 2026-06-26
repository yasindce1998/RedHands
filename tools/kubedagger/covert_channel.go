package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CovertChannelInput struct {
	Method    string `json:"method"`
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port,omitempty"`
	Data      string `json:"data,omitempty"`
	Direction string `json:"direction,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type CovertChannelTool struct {
	exec executor.Executor
}

func NewCovertChannel(exec executor.Executor) *CovertChannelTool {
	return &CovertChannelTool{exec: exec}
}

func (t *CovertChannelTool) Name() string { return "kubedagger_covert_channel" }

func (t *CovertChannelTool) Description() string {
	return "Establish covert communication channels using protocol steganography. Encodes data in ICMP payloads, IP ID fields, TCP urgent pointers, or TTL values to bypass deep packet inspection and network monitoring."
}

func (t *CovertChannelTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"method": {
				"type": "string",
				"enum": ["icmp", "ipid", "ttl", "urgent", "tcp-timestamp"],
				"description": "Covert channel encoding method"
			},
			"target": {
				"type": "string",
				"description": "Target host for the covert channel"
			},
			"port": {
				"type": "integer",
				"description": "Port to use (for TCP-based methods)"
			},
			"data": {
				"type": "string",
				"description": "Data to send through the covert channel"
			},
			"direction": {
				"type": "string",
				"enum": ["send", "receive", "bidirectional"],
				"description": "Channel direction"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to use"
			}
		},
		"required": ["method"]
	}`)
}

func (t *CovertChannelTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CovertChannelInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"covert-channel", "--method", input.Method}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}
	if input.Direction != "" {
		args = append(args, "--direction", input.Direction)
	}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger covert-channel failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Covert Channel: %s\n\n", input.Method)
	if output == "" {
		sb.WriteString("Channel established.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
