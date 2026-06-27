package tshark

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ReadInput struct {
	File   string `json:"file"`
	Filter string `json:"filter,omitempty"`
	Count  int    `json:"count,omitempty"`
	Fields string `json:"fields,omitempty"`
}

type ReadTool struct {
	exec executor.Executor
}

func NewRead(exec executor.Executor) *ReadTool {
	return &ReadTool{exec: exec}
}

func (t *ReadTool) Name() string { return "tshark_read" }

func (t *ReadTool) Description() string {
	return "Read and display packets from a pcap file with optional display filters and field selection."
}

func (t *ReadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to pcap/pcapng file"
			},
			"filter": {
				"type": "string",
				"description": "Display filter (Wireshark syntax)"
			},
			"count": {
				"type": "integer",
				"description": "Maximum packets to display"
			},
			"fields": {
				"type": "string",
				"description": "Comma-separated fields to extract (e.g., ip.src,ip.dst,tcp.port)"
			}
		},
		"required": ["file"]
	}`)
}

func (t *ReadTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ReadInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.File, "file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Fields, "fields"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-r", input.File}
	if input.Filter != "" {
		args = append(args, "-Y", input.Filter)
	}
	if input.Count > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", input.Count))
	}
	if input.Fields != "" {
		args = append(args, "-T", "fields")
		for _, f := range strings.Split(input.Fields, ",") {
			args = append(args, "-e", strings.TrimSpace(f))
		}
	}

	result, err := t.exec.Run(ctx, "tshark", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("tshark read failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## tshark Read\n\n")
	fmt.Fprintf(&sb, "**File**: %s\n\n", input.File)
	if output == "" {
		sb.WriteString("No packets matched.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
