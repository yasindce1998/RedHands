package tshark

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type StatsInput struct {
	File   string `json:"file"`
	Type   string `json:"type"`
	Filter string `json:"filter,omitempty"`
}

type StatsTool struct {
	exec executor.Executor
}

func NewStats(exec executor.Executor) *StatsTool {
	return &StatsTool{exec: exec}
}

func (t *StatsTool) Name() string { return "tshark_stats" }

func (t *StatsTool) Description() string {
	return "Generate protocol statistics from a pcap file. Supports io, conv, endpoints, and protocol hierarchy stats."
}

func (t *StatsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to pcap/pcapng file"
			},
			"type": {
				"type": "string",
				"enum": ["io", "conv,tcp", "conv,udp", "conv,ip", "endpoints,tcp", "endpoints,ip", "phs"],
				"description": "Statistics type"
			},
			"filter": {
				"type": "string",
				"description": "Display filter"
			}
		},
		"required": ["file", "type"]
	}`)
}

func (t *StatsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input StatsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.File, "file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.Type, "type"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	validTypes := map[string]bool{
		"io": true, "conv,tcp": true, "conv,udp": true, "conv,ip": true,
		"endpoints,tcp": true, "endpoints,ip": true, "phs": true,
	}
	if !validTypes[input.Type] {
		return errorResult("invalid stats type"), nil
	}

	args := []string{"-r", input.File, "-q", "-z", input.Type}
	if input.Filter != "" {
		args = append(args, "-Y", input.Filter)
	}

	result, err := t.exec.Run(ctx, "tshark", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("tshark stats failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## tshark Statistics\n\n")
	fmt.Fprintf(&sb, "**Type**: %s\n\n", input.Type)
	if output == "" {
		sb.WriteString("No statistics generated.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
