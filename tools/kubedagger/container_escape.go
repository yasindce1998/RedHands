package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ContainerEscapeInput struct {
	Action    string `json:"action"`
	Method    string `json:"method,omitempty"`
	Target    string `json:"target,omitempty"`
	Command   string `json:"command,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type ContainerEscapeTool struct {
	exec executor.Executor
}

func NewContainerEscape(exec executor.Executor) *ContainerEscapeTool {
	return &ContainerEscapeTool{exec: exec}
}

func (t *ContainerEscapeTool) Name() string { return "kubedagger_escape" }

func (t *ContainerEscapeTool) Description() string {
	return "Detect and execute container escape techniques. Checks for privileged containers, mounted docker sockets, writable hostPath, kernel exploits, and nsenter-based escapes. Can execute breakout to host namespace."
}

func (t *ContainerEscapeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["detect", "execute"],
				"description": "detect: check for escape vectors; execute: perform container escape"
			},
			"method": {
				"type": "string",
				"enum": ["privileged", "docker-socket", "hostpath", "nsenter", "cgroups", "kernel-exploit", "auto"],
				"description": "Escape method to use (auto selects best available)"
			},
			"target": {
				"type": "string",
				"description": "Target container ID (default: current container)"
			},
			"command": {
				"type": "string",
				"description": "Command to execute on host after escape"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace for pod-level escapes"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ContainerEscapeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ContainerEscapeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Command, "command"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"escape", input.Action}
	if input.Method != "" {
		args = append(args, "--method", input.Method)
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Command != "" {
		args = append(args, "--command", input.Command)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger escape failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Container Escape: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
