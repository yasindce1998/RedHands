package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var detectorActions = []string{"list", "info"}

type DetectorsInput struct {
	Action string `json:"action"`
	Name   string `json:"name,omitempty"`
}

type DetectorsTool struct {
	exec executor.Executor
}

func NewDetectors(exec executor.Executor) *DetectorsTool {
	return &DetectorsTool{exec: exec}
}

func (t *DetectorsTool) Name() string { return "barzakh_detectors" }

func (t *DetectorsTool) Description() string {
	return "List the 138 built-in barzakh-scanner bootkit detectors, or show detailed information (description, severity, applicable scan types) for a single detector by name."
}

func (t *DetectorsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "info"],
				"description": "list all detectors or show info for one detector"
			},
			"name": {
				"type": "string",
				"description": "Detector name (required for info)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *DetectorsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DetectorsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	validActions := make(map[string]bool, len(detectorActions))
	for _, a := range detectorActions {
		validActions[a] = true
	}
	if !validActions[input.Action] {
		return errorResult("invalid action: must be one of " + strings.Join(detectorActions, ", ")), nil
	}
	if input.Action == "info" && input.Name == "" {
		return errorResult("name is required for info"), nil
	}
	if err := validateName(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"detectors", input.Action}
	if input.Action == "info" {
		// `detectors info` takes the detector name as a positional argument
		// in the pinned barzakh-scanner release (v0.7.0), not a --name flag.
		args = append(args, input.Name)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner detectors %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	if input.Action == "list" {
		sb.WriteString("## Available Barzakh Detectors\n\n")
	} else {
		fmt.Fprintf(&sb, "## Detector Info: %s\n\n", input.Name)
	}
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
