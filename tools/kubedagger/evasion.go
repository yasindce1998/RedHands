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
	Mode string `json:"mode,omitempty"`
}

type EvasionTool struct {
	exec executor.Executor
}

func NewEvasion(exec executor.Executor) *EvasionTool {
	return &EvasionTool{exec: exec}
}

func (t *EvasionTool) Name() string { return "kubedagger_evasion" }

func (t *EvasionTool) Description() string {
	return "Evade container-native runtime security sensors (Falco, Tetragon, Sysdig, Tracee) by neutralizing their eBPF-based event collection. Modes target sensor programs, probe endpoints, or shield the agent from detection. Use 'all' to apply every evasion technique."
}

func (t *EvasionTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["cnative-sensor", "cnative-probe", "cnative-shield", "all"],
				"description": "Evasion mode (default: all)"
			}
		}
	}`)
}

func (t *EvasionTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EvasionInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"evasion"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
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
	mode := input.Mode
	if mode == "" {
		mode = "all"
	}
	fmt.Fprintf(&sb, "## KubeDagger Evasion: %s\n\n", mode)
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
