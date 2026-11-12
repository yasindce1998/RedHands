package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ValidateInput struct {
	Corpus string `json:"corpus"`
	JSON   bool   `json:"json,omitempty"`
}

type ValidateTool struct {
	exec executor.Executor
}

func NewValidate(exec executor.Executor) *ValidateTool {
	return &ValidateTool{exec: exec}
}

func (t *ValidateTool) Name() string { return "barzakh_validate" }

func (t *ValidateTool) Description() string {
	return "Validate a generated UEFI bootkit test corpus: verifies that malicious samples are detected by barzakh-scanner and clean samples are not, reporting detection coverage gaps. Read-only analysis of an existing corpus directory produced by barzakh_corpus."
}

func (t *ValidateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"corpus": {
				"type": "string",
				"description": "Path to the corpus directory produced by barzakh_corpus"
			},
			"json": {
				"type": "boolean",
				"description": "Emit structured JSON validation results"
			}
		},
		"required": ["corpus"]
	}`)
}

func (t *ValidateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ValidateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Corpus == "" {
		return errorResult("corpus path is required"), nil
	}
	if err := validatePath(input.Corpus, "corpus"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"validate", "--corpus", input.Corpus}
	if input.JSON {
		args = append(args, "--json")
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary validate failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Corpus Validation Results\n\n")
	fmt.Fprintf(&sb, "- **Corpus:** %s\n", input.Corpus)
	if output == "" {
		sb.WriteString("\nValidation completed (no output).\n")
	} else if input.JSON {
		sb.WriteString("\n```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
