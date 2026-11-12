package kubedagger

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type OperatorStatusInput struct {
	Key    string `json:"key,omitempty"`
	Addr   string `json:"addr,omitempty"`
	TaskID string `json:"task_id"`
}

type OperatorStatusTool struct {
	exec executor.Executor
}

func NewOperatorStatus(exec executor.Executor) *OperatorStatusTool {
	return &OperatorStatusTool{exec: exec}
}

func (t *OperatorStatusTool) Name() string { return "kubedagger_operator_status" }

func (t *OperatorStatusTool) Description() string {
	return "Check the status of an asynchronous task dispatched through the KubeDagger operator. Returns the current state and any output produced by the task."
}

func (t *OperatorStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"key": {
				"type": "string",
				"description": "Operator API key (required; falls back to KUBEDAGGER_OPERATOR_KEY env var)"
			},
			"addr": {
				"type": "string",
				"description": "Operator address (default: 127.0.0.1:9443)"
			},
			"task_id": {
				"type": "string",
				"description": "Task ID to check (required)"
			}
		},
		"required": ["key", "task_id"]
	}`)
}

func (t *OperatorStatusTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorStatusInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.TaskID == "" {
		return errorResult("task_id is required"), nil
	}
	if err := validateSafeString(input.TaskID, "task_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	globalArgs, err := operatorGlobalArgs(input.Key, input.Addr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	args := append(globalArgs, "status", input.TaskID)

	result, err := t.exec.Run(ctx, "kubedagger-operator", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult("kubedagger operator status failed: " + err.Error() + "\n" + stderr), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Operator Task Status\n\n")
	if output == "" {
		sb.WriteString("No status available.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
