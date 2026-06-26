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
	Action    string `json:"action"`
	Namespace string `json:"namespace,omitempty"`
	Target    string `json:"target,omitempty"`
	Depth     string `json:"depth,omitempty"`
}

type HoneypotDetectTool struct {
	exec executor.Executor
}

func NewHoneypotDetect(exec executor.Executor) *HoneypotDetectTool {
	return &HoneypotDetectTool{exec: exec}
}

func (t *HoneypotDetectTool) Name() string { return "kubedagger_honeypot_detect" }

func (t *HoneypotDetectTool) Description() string {
	return "Detect honeypots, canary tokens, and deception infrastructure in the cluster. Identifies honeypot pods, fake credentials, canary files, and deception services by analyzing resource patterns, response timing, and metadata inconsistencies."
}

func (t *HoneypotDetectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["scan", "identify", "avoid", "map"],
				"description": "Detection action: scan cluster, identify specific target, configure avoidance, map all deception"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace to scan"
			},
			"target": {
				"type": "string",
				"description": "Specific resource to check"
			},
			"depth": {
				"type": "string",
				"enum": ["quick", "normal", "deep"],
				"description": "Scan depth"
			}
		},
		"required": ["action"]
	}`)
}

func (t *HoneypotDetectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HoneypotDetectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"honeypot-detect", "--action", input.Action}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Depth != "" {
		args = append(args, "--depth", input.Depth)
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
	fmt.Fprintf(&sb, "## KubeDagger Honeypot Detect: %s\n\n", input.Action)
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
