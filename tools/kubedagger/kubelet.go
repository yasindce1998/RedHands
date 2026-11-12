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
	Action string `json:"action,omitempty"`
	Node   string `json:"node,omitempty"`
	Pod    string `json:"pod,omitempty"`
	Cmd    string `json:"cmd,omitempty"`
}

type KubeletTool struct {
	exec executor.Executor
}

func NewKubelet(exec executor.Executor) *KubeletTool {
	return &KubeletTool{exec: exec}
}

func (t *KubeletTool) Name() string { return "kubedagger_kubelet" }

func (t *KubeletTool) Description() string {
	return "Abuse the kubelet API (port 10250/10255) for unauthenticated or token-based container access. Lists pods on a node, executes commands in containers, and extracts secrets by interacting directly with the node kubelet, bypassing API server audit logs."
}

func (t *KubeletTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["exec", "list", "secrets"],
				"description": "Kubelet API action (default: list)"
			},
			"node": {
				"type": "string",
				"description": "Target node IP or hostname"
			},
			"pod": {
				"type": "string",
				"description": "Target pod name (required for exec)"
			},
			"cmd": {
				"type": "string",
				"description": "Command to exec in the container (default: id)"
			}
		}
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
	if err := validateSafeString(input.Cmd, "cmd"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"kubelet"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Node != "" {
		args = append(args, "--node", input.Node)
	}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Cmd != "" {
		args = append(args, "--cmd", input.Cmd)
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
	action := input.Action
	if action == "" {
		action = "list"
	}
	fmt.Fprintf(&sb, "## KubeDagger Kubelet: %s\n\n", action)
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
