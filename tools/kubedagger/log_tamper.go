package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type LogTamperInput struct {
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Replace string `json:"replace,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

type LogTamperTool struct {
	exec executor.Executor
}

func NewLogTamper(exec executor.Executor) *LogTamperTool {
	return &LogTamperTool{exec: exec}
}

func (t *LogTamperTool) Name() string { return "kubedagger_log_tamper" }

func (t *LogTamperTool) Description() string {
	return "Tamper with log output by hooking write syscalls of logging processes. Can suppress specific log lines, modify content in-flight, or inject false entries. Works on container logs, journald, syslog, and application logs."
}

func (t *LogTamperTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["suppress", "modify", "inject", "truncate"],
				"description": "Tampering action"
			},
			"target": {
				"type": "string",
				"description": "Target log source (process name, log path, or 'all')"
			},
			"pattern": {
				"type": "string",
				"description": "Pattern to match for suppression/modification"
			},
			"replace": {
				"type": "string",
				"description": "Replacement content for modify action"
			},
			"pid": {
				"type": "integer",
				"description": "Target process ID"
			}
		},
		"required": ["action"]
	}`)
}

func (t *LogTamperTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input LogTamperInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Pattern, "pattern"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Replace, "replace"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"log-tamper", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Pattern != "" {
		args = append(args, "--pattern", input.Pattern)
	}
	if input.Replace != "" {
		args = append(args, "--replace", input.Replace)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger log-tamper failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Log Tamper: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Tamper active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
