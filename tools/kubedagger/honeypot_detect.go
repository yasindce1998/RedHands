package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type HoneypotDetectInput struct {
	Checks string `json:"checks,omitempty"`
}

type HoneypotDetectTool struct {
	exec executor.Executor
}

func NewHoneypotDetect(exec executor.Executor) *HoneypotDetectTool {
	return &HoneypotDetectTool{exec: exec}
}

func (t *HoneypotDetectTool) Name() string { return "kubedagger_honeypot_detect" }

func (t *HoneypotDetectTool) Description() string {
	return "Detect honeypots, canary tokens, and deception infrastructure in the cluster. Probes kubelet endpoints, metrics services, and token patterns to identify decoy resources before committing to operations."
}

func (t *HoneypotDetectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"checks": {
				"type": "string",
				"enum": ["all", "kubelet", "metrics", "tokens"],
				"description": "Detection checks to run (default: all)"
			}
		}
	}`)
}

func (t *HoneypotDetectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HoneypotDetectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"honeypot-detect"}
	if input.Checks != "" {
		args = append(args, "--checks", input.Checks)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger honeypot-detect failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Honeypot Detect\n\n")
	if output == "" {
		sb.WriteString("No honeypots detected.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
