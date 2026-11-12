package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type RobustnessInput struct {
	Filter    string `json:"filter,omitempty"`
	Mutations string `json:"mutations,omitempty"`
	JSON      bool   `json:"json,omitempty"`
}

type RobustnessTool struct {
	exec executor.Executor
}

func NewRobustness(exec executor.Executor) *RobustnessTool {
	return &RobustnessTool{exec: exec}
}

func (t *RobustnessTool) Name() string { return "barzakh_robustness" }

func (t *RobustnessTool) Description() string {
	return "Run detection robustness testing: mutate payload samples and re-scan them to measure how reliably barzakh-scanner detects modified bootkits. Useful for estimating detector evasion difficulty before a red-team engagement."
}

func (t *RobustnessTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"filter": {
				"type": "string",
				"description": "Restrict robustness testing to payloads matching this filter"
			},
			"mutations": {
				"type": "string",
				"description": "Number of mutations to generate per payload"
			},
			"json": {
				"type": "boolean",
				"description": "Emit structured JSON results"
			}
		},
		"required": []
	}`)
}

func (t *RobustnessTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RobustnessInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.Mutations, "mutations"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"robustness"}
	if input.Filter != "" {
		args = append(args, "--filter", input.Filter)
	}
	if input.Mutations != "" {
		args = append(args, "--mutations", input.Mutations)
	}
	if input.JSON {
		args = append(args, "--json")
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary robustness failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Detection Robustness Results\n\n")
	if input.Filter != "" {
		fmt.Fprintf(&sb, "- **Filter:** %s\n", input.Filter)
	}
	if input.Mutations != "" {
		fmt.Fprintf(&sb, "- **Mutations per payload:** %s\n", input.Mutations)
	}
	if output == "" {
		sb.WriteString("\nRobustness testing completed (no output).\n")
	} else if input.JSON {
		sb.WriteString("\n```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
