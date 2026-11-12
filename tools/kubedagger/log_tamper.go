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
	Mode      string `json:"mode,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	LogTarget string `json:"log_target,omitempty"`
}

type LogTamperTool struct {
	exec executor.Executor
}

func NewLogTamper(exec executor.Executor) *LogTamperTool {
	return &LogTamperTool{exec: exec}
}

func (t *LogTamperTool) Name() string { return "kubedagger_log_tamper" }

func (t *LogTamperTool) Description() string {
	return "Tamper with log output by hooking write syscalls of logging processes. Drops, modifies, or injects log lines matching a pattern in syslog, journald, or container logs. Patterns are regexes restricted to plain characters (no shell metacharacters such as quotes, parentheses, or pipes)."
}

func (t *LogTamperTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["drop", "modify", "inject"],
				"description": "Tampering mode (default: drop)"
			},
			"pattern": {
				"type": "string",
				"description": "Regex pattern of log lines to target (no shell metacharacters allowed)"
			},
			"log_target": {
				"type": "string",
				"enum": ["syslog", "journald", "container"],
				"description": "Log source to tamper with (default: syslog)"
			}
		}
	}`)
}

func (t *LogTamperTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input LogTamperInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	// Note: the executor rejects shell metacharacters, so regex patterns are
	// validated with validateSafeString exactly like every other free-text
	// field; complex regexes must be expressed without those characters.
	if err := validateSafeString(input.Pattern, "pattern"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"log-tamper"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.Pattern != "" {
		args = append(args, "--pattern", input.Pattern)
	}
	if input.LogTarget != "" {
		args = append(args, "--log-target", input.LogTarget)
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
	sb.WriteString("## KubeDagger Log Tamper\n\n")
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
