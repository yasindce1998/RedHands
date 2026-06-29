package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CorpusInput struct {
	Output string `json:"output,omitempty"`
}

type CorpusTool struct {
	exec executor.Executor
}

func NewCorpus(exec executor.Executor) *CorpusTool {
	return &CorpusTool{exec: exec}
}

func (t *CorpusTool) Name() string { return "barzakh_corpus" }

func (t *CorpusTool) Description() string {
	return "Generate a full test corpus of malicious UEFI firmware images paired with clean counterparts. Useful for building detection evasion test suites or training datasets."
}

func (t *CorpusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"output": {
				"type": "string",
				"description": "Output directory for corpus files (default: ./corpus)"
			}
		},
		"required": []
	}`)
}

func (t *CorpusTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CorpusInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"corpus"}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary corpus failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## UEFI Bootkit Corpus Generation\n\n")
	if input.Output != "" {
		fmt.Fprintf(&sb, "- **Output directory:** %s\n\n", input.Output)
	}
	if output == "" {
		sb.WriteString("Corpus generated successfully.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
