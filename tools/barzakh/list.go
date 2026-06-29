package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ListTool struct {
	exec executor.Executor
}

func NewList(exec executor.Executor) *ListTool {
	return &ListTool{exec: exec}
}

func (t *ListTool) Name() string { return "barzakh_list" }

func (t *ListTool) Description() string {
	return "List all available UEFI bootkit payloads that can be generated for red-team engagements. Shows payload name, target architecture, and expected detection signatures."
}

func (t *ListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {},
		"required": []
	}`)
}

func (t *ListTool) Execute(ctx context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	result, err := t.exec.Run(ctx, "barzakh-adversary", "list")
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary list failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Available UEFI Bootkit Payloads\n\n")
	if output == "" {
		sb.WriteString("No payloads available.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
