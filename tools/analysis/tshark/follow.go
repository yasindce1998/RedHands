package tshark

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FollowInput struct {
	File     string `json:"file"`
	Protocol string `json:"protocol"`
	Stream   int    `json:"stream"`
	Filter   string `json:"filter,omitempty"`
}

type FollowTool struct {
	exec executor.Executor
}

func NewFollow(exec executor.Executor) *FollowTool {
	return &FollowTool{exec: exec}
}

func (t *FollowTool) Name() string { return "tshark_follow" }

func (t *FollowTool) Description() string {
	return "Follow and reconstruct a protocol stream from a pcap file. Supports TCP, UDP, HTTP, and TLS streams."
}

func (t *FollowTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to pcap/pcapng file"
			},
			"protocol": {
				"type": "string",
				"enum": ["tcp", "udp", "http", "tls"],
				"description": "Protocol stream to follow"
			},
			"stream": {
				"type": "integer",
				"description": "Stream index number"
			},
			"filter": {
				"type": "string",
				"description": "Additional display filter"
			}
		},
		"required": ["file", "protocol", "stream"]
	}`)
}

func (t *FollowTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FollowInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.File, "file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.Protocol, "protocol"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	validProtocols := map[string]bool{"tcp": true, "udp": true, "http": true, "tls": true}
	if !validProtocols[input.Protocol] {
		return errorResult("protocol must be one of: tcp, udp, http, tls"), nil
	}

	followArg := fmt.Sprintf("%s,ascii,%d", input.Protocol, input.Stream)
	args := []string{"-r", input.File, "-q", "-z", "follow," + followArg}
	if input.Filter != "" {
		args = append(args, "-Y", input.Filter)
	}

	result, err := t.exec.Run(ctx, "tshark", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("tshark follow failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## tshark Follow Stream\n\n")
	fmt.Fprintf(&sb, "**Protocol**: %s | **Stream**: %d\n\n", input.Protocol, input.Stream)
	if output == "" {
		sb.WriteString("No stream data.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
