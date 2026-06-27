package john

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ShowInput struct {
	HashFile string `json:"hash_file"`
	Format   string `json:"format,omitempty"`
}

type ShowTool struct {
	exec executor.Executor
}

func NewShow(exec executor.Executor) *ShowTool {
	return &ShowTool{exec: exec}
}

func (t *ShowTool) Name() string { return "john_show" }

func (t *ShowTool) Description() string {
	return "Show previously cracked passwords from John's pot file. Displays username:password pairs for cracked entries."
}

func (t *ShowTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hash_file": {
				"type": "string",
				"description": "Path to file containing hashes"
			},
			"format": {
				"type": "string",
				"description": "Hash format"
			}
		},
		"required": ["hash_file"]
	}`)
}

func (t *ShowTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ShowInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.HashFile, "hash_file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Format, "format"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"--show", input.HashFile}
	if input.Format != "" {
		args = append(args, fmt.Sprintf("--format=%s", input.Format))
	}

	result, err := t.exec.Run(ctx, "john", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("john show failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## John Show\n\n")
	if output == "" {
		sb.WriteString("No cracked passwords found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
