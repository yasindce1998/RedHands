package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DetectionInput struct {
	Action     string `json:"action"`
	Techniques string `json:"techniques,omitempty"`
	Out        string `json:"out,omitempty"`
}

type DetectionTool struct {
	exec executor.Executor
}

func NewDetection(exec executor.Executor) *DetectionTool {
	return &DetectionTool{exec: exec}
}

func (t *DetectionTool) Name() string { return "kubedagger_detection" }

func (t *DetectionTool) Description() string {
	return "Browse KubeDagger detection coverage. 'list' prints the markdown catalog of available detection techniques; 'generate' produces detection content (e.g. Falco/Sigma rules) for the given comma-separated techniques, or all by default."
}

func (t *DetectionTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "generate"],
				"description": "list: show the detection catalog; generate: produce detection content"
			},
			"techniques": {
				"type": "string",
				"description": "Comma-separated technique IDs to generate for (generate only; default: all)"
			},
			"out": {
				"type": "string",
				"description": "Output file path (generate only; default: stdout)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *DetectionTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DetectionInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Action == "" {
		return errorResult("action is required"), nil
	}
	switch input.Action {
	case "list", "generate":
	default:
		return errorResult("invalid action: must be 'list' or 'generate'"), nil
	}
	if err := validateSafeString(input.Techniques, "techniques"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Out, "out"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	if input.Action == "list" {
		args = []string{"detection", "list"}
	} else {
		args = []string{"detection", "generate"}
		if input.Techniques != "" {
			args = append(args, "--techniques", input.Techniques)
		}
		if input.Out != "" {
			args = append(args, "--out", input.Out)
		}
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger detection %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Detection: %s\n\n", input.Action)
	if output == "" {
		if input.Action == "generate" && input.Out != "" {
			fmt.Fprintf(&sb, "Detection content written to %s\n", input.Out)
		} else {
			sb.WriteString("No detection content available.\n")
		}
	} else {
		sb.WriteString(output)
		sb.WriteString("\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
