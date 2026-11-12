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
	Action    string `json:"action,omitempty"`
	Technique string `json:"technique,omitempty"`
}

type ContainerEscapeTool struct {
	exec executor.Executor
}

func NewContainerEscape(exec executor.Executor) *ContainerEscapeTool {
	return &ContainerEscapeTool{exec: exec}
}

func (t *ContainerEscapeTool) Name() string { return "kubedagger_escape" }

func (t *ContainerEscapeTool) Description() string {
	return "Detect and execute container escape techniques. Checks for privileged containers, hostPath mounts, host PID/network namespaces, and other breakout vectors. Use action 'detect' to enumerate vectors or 'execute' to perform the escape."
}

func (t *ContainerEscapeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["detect", "execute"],
				"description": "detect: check for escape vectors; execute: perform container escape (default: detect)"
			},
			"technique": {
				"type": "string",
				"enum": ["privileged", "hostpath", "hostpid", "hostnet", "all"],
				"description": "Escape technique to use (default: all)"
			}
		}
	}`)
}

func (t *ContainerEscapeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ContainerEscapeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"escape"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Technique != "" {
		args = append(args, "--technique", input.Technique)
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
	action := input.Action
	if action == "" {
		action = "detect"
	}
	fmt.Fprintf(&sb, "## KubeDagger Container Escape: %s\n\n", action)
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
