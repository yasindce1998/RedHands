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
		// Debian/Ubuntu ship core John the Ripper (not the jumbo fork),
		// which has no --list. Degrade to the core format registry
		// instead of failing: core supports exactly these formats.
		if strings.Contains(stderr, "Unknown option") || strings.Contains(string(result.Stdout), "Unknown option") {
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: "## John the Ripper Formats\n\n" +
					"The installed john is a core build (no `--list` support; Debian/Ubuntu packages). " +
					"Core builds support only the built-in format registry:\n\n" +
					"```\nAFS, BF, BSDI, DES, LM, MD5, crypt, trip\n```\n\n" +
					"Install a jumbo build (upstream release tarball, or a distro jumbo package) for the full format list."}},
			}, nil
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
