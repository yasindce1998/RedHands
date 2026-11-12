package kubedagger

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ProctreeInput struct{}

type ProctreeTool struct {
	exec executor.Executor
}

func NewProctree(exec executor.Executor) *ProctreeTool {
	return &ProctreeTool{exec: exec}
}

func (t *ProctreeTool) Name() string { return "kubedagger_proctree" }

func (t *ProctreeTool) Description() string {
	return "Dump the current process tree as observed via eBPF process lifecycle hooks. Reveals hidden or short-lived processes that procfs-based tools miss."
}

func (t *ProctreeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`)
}

func (t *ProctreeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ProctreeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"proctree", "get"}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult("kubedagger proctree get failed: " + err.Error() + "\n" + stderr), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Process Tree\n\n")
	if output == "" {
		sb.WriteString("No processes captured.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
