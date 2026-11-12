package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PipeProgInput struct {
	Action  string `json:"action"`
	Program string `json:"program,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Backup  bool   `json:"backup,omitempty"`
}

type PipeProgTool struct {
	exec executor.Executor
}

func NewPipeProg(exec executor.Executor) *PipeProgTool {
	return &PipeProgTool{exec: exec}
}

func (t *PipeProgTool) Name() string { return "kubedagger_pipe_prog" }

func (t *PipeProgTool) Description() string {
	return "Manage covert program execution through named pipes. 'put' loads a program (path must not contain '_') into the pipe between a source and destination name, optionally backing up the original; 'delete' removes the pipe program mapping."
}

func (t *PipeProgTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["put", "delete"],
				"description": "Pipe program action"
			},
			"program": {
				"type": "string",
				"description": "Path to the program to load (put only; must not contain '_')"
			},
			"from": {
				"type": "string",
				"description": "Source pipe name (max 16 chars, no '#')"
			},
			"to": {
				"type": "string",
				"description": "Destination pipe name (1-16 chars, no '#')"
			},
			"backup": {
				"type": "boolean",
				"description": "put only: back up the original pipe target before replacing"
			}
		},
		"required": ["action"]
	}`)
}

// validatePipeName enforces the pipe_prog --from/--to constraints:
// 1-16 chars and no '#'.
func validatePipeName(s, field string) error {
	if s == "" {
		return nil
	}
	if len(s) < 1 || len(s) > 16 {
		return fmt.Errorf("%s must be 1-16 chars", field)
	}
	if strings.Contains(s, "#") {
		return fmt.Errorf("%s must not contain '#'", field)
	}
	return nil
}

func (t *PipeProgTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PipeProgInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Action == "" {
		return errorResult("action is required"), nil
	}
	switch input.Action {
	case "put", "delete":
	default:
		return errorResult("invalid action: must be 'put' or 'delete'"), nil
	}

	if err := validatePipeName(input.From, "from"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePipeName(input.To, "to"); err != nil {
		return errorResult(err.Error()), nil
	}

	if input.Action == "put" {
		if input.Program == "" {
			return errorResult("program is required for action=put"), nil
		}
		if strings.Contains(input.Program, "_") {
			return errorResult("program must not contain '_'"), nil
		}
		if err := validateSafeString(input.Program, "program"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"pipe_prog"}
	if input.Action == "put" {
		args = append(args, "put", input.Program)
	} else {
		args = append(args, "delete")
	}
	if input.From != "" {
		args = append(args, "--from", input.From)
	}
	if input.To != "" {
		args = append(args, "--to", input.To)
	}
	if input.Action == "put" && input.Backup {
		args = append(args, "--backup")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger pipe_prog %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Pipe Prog: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
