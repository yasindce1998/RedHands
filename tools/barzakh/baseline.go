package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var baselineActions = []string{"create", "show"}

type BaselineInput struct {
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
}

type BaselineTool struct {
	exec executor.Executor
}

func NewBaseline(exec executor.Executor) *BaselineTool {
	return &BaselineTool{exec: exec}
}

func (t *BaselineTool) Name() string { return "barzakh_baseline" }

func (t *BaselineTool) Description() string {
	return "Create a known-good firmware baseline for drift comparison (baseline create from a trusted image), or show the currently stored baseline (baseline show). Baselines are used by barzakh_scan to flag firmware modifications."
}

func (t *BaselineTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["create", "show"],
				"description": "create a baseline from a trusted image, or show the stored baseline"
			},
			"target": {
				"type": "string",
				"description": "Path to the trusted UEFI firmware image (required for create)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *BaselineTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input BaselineInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	validActions := make(map[string]bool, len(baselineActions))
	for _, a := range baselineActions {
		validActions[a] = true
	}
	if !validActions[input.Action] {
		return errorResult("invalid action: must be one of " + strings.Join(baselineActions, ", ")), nil
	}
	if input.Action == "create" && input.Target == "" {
		return errorResult("target is required for create"), nil
	}
	if err := validatePath(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"baseline", input.Action}
	if input.Action == "create" {
		args = append(args, "--target", input.Target)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner baseline %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	if input.Action == "create" {
		sb.WriteString("## Baseline Creation\n\n")
		fmt.Fprintf(&sb, "- **Target:** %s\n", input.Target)
	} else {
		sb.WriteString("## Stored Baseline\n\n")
	}
	if output == "" {
		sb.WriteString("Completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
