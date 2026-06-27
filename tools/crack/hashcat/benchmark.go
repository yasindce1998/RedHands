package hashcat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type BenchmarkInput struct {
	HashType int `json:"hash_type,omitempty"`
}

type BenchmarkTool struct {
	exec executor.Executor
}

func NewBenchmark(exec executor.Executor) *BenchmarkTool {
	return &BenchmarkTool{exec: exec}
}

func (t *BenchmarkTool) Name() string { return "hashcat_benchmark" }

func (t *BenchmarkTool) Description() string {
	return "Benchmark Hashcat performance for hash types. Shows cracking speed (H/s) for available hardware to estimate attack duration."
}

func (t *BenchmarkTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hash_type": {
				"type": "integer",
				"description": "Specific hash type to benchmark (omit for all types)"
			}
		}
	}`)
}

func (t *BenchmarkTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input BenchmarkInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"-b"}
	if input.HashType > 0 {
		args = append(args, "-m", fmt.Sprintf("%d", input.HashType))
	}

	result, err := t.exec.Run(ctx, "hashcat", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("hashcat benchmark failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Hashcat Benchmark\n\n")
	if output == "" {
		sb.WriteString("Benchmark complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
