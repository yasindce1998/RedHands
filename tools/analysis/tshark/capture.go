package tshark

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CaptureInput struct {
	Interface string `json:"interface"`
	Filter    string `json:"filter,omitempty"`
	Duration  int    `json:"duration,omitempty"`
	Count     int    `json:"count,omitempty"`
	Output    string `json:"output,omitempty"`
}

type CaptureTool struct {
	exec executor.Executor
}

func NewCapture(exec executor.Executor) *CaptureTool {
	return &CaptureTool{exec: exec}
}

func (t *CaptureTool) Name() string { return "tshark_capture" }

func (t *CaptureTool) Description() string {
	return "Capture network packets using tshark. Specify interface, capture filter, duration, and packet count limits."
}

func (t *CaptureTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Network interface to capture on (e.g., eth0)"
			},
			"filter": {
				"type": "string",
				"description": "Capture filter (BPF syntax)"
			},
			"duration": {
				"type": "integer",
				"description": "Capture duration in seconds"
			},
			"count": {
				"type": "integer",
				"description": "Maximum number of packets to capture"
			},
			"output": {
				"type": "string",
				"description": "Output pcap file path"
			}
		},
		"required": ["interface"]
	}`)
}

func (t *CaptureTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CaptureInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-i", input.Interface}
	if input.Filter != "" {
		args = append(args, "-f", input.Filter)
	}
	if input.Duration > 0 {
		args = append(args, "-a", fmt.Sprintf("duration:%d", input.Duration))
	}
	if input.Count > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", input.Count))
	}
	if input.Output != "" {
		args = append(args, "-w", input.Output)
	}

	result, err := t.exec.Run(ctx, "tshark", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("tshark capture failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## tshark Capture\n\n")
	fmt.Fprintf(&sb, "**Interface**: %s\n\n", input.Interface)
	if output == "" {
		sb.WriteString("Capture complete (output written to file).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
