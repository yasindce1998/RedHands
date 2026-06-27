package hashcat

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
	HashType int    `json:"hash_type"`
	Potfile  string `json:"potfile,omitempty"`
}

type ShowTool struct {
	exec executor.Executor
}

func NewShow(exec executor.Executor) *ShowTool {
	return &ShowTool{exec: exec}
}

func (t *ShowTool) Name() string { return "hashcat_show" }

func (t *ShowTool) Description() string {
	return "Show previously cracked hashes from the Hashcat potfile. Displays hash:password pairs for already-cracked entries."
}

func (t *ShowTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hash_file": {
				"type": "string",
				"description": "Path to file containing hashes"
			},
			"hash_type": {
				"type": "integer",
				"description": "Hash type code"
			},
			"potfile": {
				"type": "string",
				"description": "Path to potfile (optional)"
			}
		},
		"required": ["hash_file", "hash_type"]
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
	if err := validateSafeString(input.Potfile, "potfile"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-m", fmt.Sprintf("%d", input.HashType), "--show", input.HashFile}
	if input.Potfile != "" {
		args = append(args, "--potfile-path", input.Potfile)
	}

	result, err := t.exec.Run(ctx, "hashcat", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("hashcat show failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Hashcat Show\n\n")
	if output == "" {
		sb.WriteString("No cracked hashes found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
