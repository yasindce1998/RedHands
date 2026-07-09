package reporting

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type ExecutiveSummaryTool struct {
	store *targetdb.Store
}

func NewExecutiveSummaryTool(store *targetdb.Store) *ExecutiveSummaryTool {
	return &ExecutiveSummaryTool{store: store}
}

func (t *ExecutiveSummaryTool) Name() string { return "report_executive" }

func (t *ExecutiveSummaryTool) Description() string {
	return "Generate an executive summary report from current findings and host data"
}

func (t *ExecutiveSummaryTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"title": {"type": "string", "description": "Report title"},
			"format": {"type": "string", "description": "Output format (markdown or json)", "enum": ["markdown", "json"]}
		}
	}`)
}

func (t *ExecutiveSummaryTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Title  string `json:"title"`
		Format string `json:"format"`
	}
	if len(params) > 0 {
		json.Unmarshal(params, &input)
	}
	if input.Format == "" {
		input.Format = "markdown"
	}

	findings := t.store.QueryFindings("", "", "")
	hosts := t.store.ListHosts()

	summary := report.GenerateExecutiveSummary(findings, hosts, input.Title)

	switch input.Format {
	case "json":
		return jsonResult(summary)
	default:
		return textResult(summary.RenderMarkdown())
	}
}
