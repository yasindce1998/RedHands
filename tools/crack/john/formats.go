package john

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FormatsInput struct {
	Filter string `json:"filter,omitempty"`
}

type FormatsTool struct {
	exec executor.Executor
}

func NewFormats(exec executor.Executor) *FormatsTool {
	return &FormatsTool{exec: exec}
}

func (t *FormatsTool) Name() string { return "john_formats" }

func (t *FormatsTool) Description() string {
	return "List available hash formats supported by John the Ripper. Use filter to search for specific format names."
}

func (t *FormatsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"filter": {
				"type": "string",
				"description": "Filter formats by name substring"
			}
		}
	}`)
}

func (t *FormatsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FormatsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"--list=formats"}

	result, err := t.exec.Run(ctx, "john", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult("john formats failed: " + err.Error() + "\n" + stderr), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	if input.Filter != "" {
		lines := strings.Split(output, "\n")
		var filtered []string
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(input.Filter)) {
				filtered = append(filtered, line)
			}
		}
		output = strings.Join(filtered, "\n")
	}

	var sb strings.Builder
	sb.WriteString("## John Formats\n\n")
	if output == "" {
		sb.WriteString("No matching formats found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
