package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var intelActions = []string{"feeds", "misp", "attack", "stix"}

type IntelInput struct {
	Action string `json:"action"`
}

type IntelTool struct {
	exec executor.Executor
}

func NewIntel(exec executor.Executor) *IntelTool {
	return &IntelTool{exec: exec}
}

func (t *IntelTool) Name() string { return "barzakh_intel" }

func (t *IntelTool) Description() string {
	return "Query threat intelligence used by barzakh-scanner: list configured IOC feeds (feeds), or query MISP events, MITRE ATT&CK technique mappings, and STIX indicators relevant to UEFI bootkits."
}

func (t *IntelTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["feeds", "misp", "attack", "stix"],
				"description": "intel source to query"
			}
		},
		"required": ["action"]
	}`)
}

func (t *IntelTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input IntelInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	validActions := make(map[string]bool, len(intelActions))
	for _, a := range intelActions {
		validActions[a] = true
	}
	if !validActions[input.Action] {
		return errorResult("invalid action: must be one of " + strings.Join(intelActions, ", ")), nil
	}

	args := []string{"intel", input.Action}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner intel %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Barzakh Intel: %s\n\n", input.Action)
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
