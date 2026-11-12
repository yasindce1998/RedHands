package kubedagger

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type MITREExportInput struct {
	Format string `json:"format,omitempty"`
}

type MITREExportTool struct {
	exec executor.Executor
}

func NewMITREExport(exec executor.Executor) *MITREExportTool {
	return &MITREExportTool{exec: exec}
}

func (t *MITREExportTool) Name() string { return "kubedagger_mitre_export" }

func (t *MITREExportTool) Description() string {
	return "Export the MITRE ATT&CK mapping of KubeDagger techniques and collected events. Produces a JSON or Markdown report of technique coverage and observed activity mapped to tactics."
}

func (t *MITREExportTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"format": {
				"type": "string",
				"enum": ["json", "markdown"],
				"description": "Export format (default: json)"
			}
		}
	}`)
}

func (t *MITREExportTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MITREExportInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"mitre", "export"}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult("kubedagger mitre export failed: " + err.Error() + "\n" + stderr), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger MITRE ATT&CK Export\n\n")
	if output == "" {
		sb.WriteString("No mapping available.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
