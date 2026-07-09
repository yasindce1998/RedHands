package reporting

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type SARIFTool struct {
	store *targetdb.Store
}

func NewSARIFTool(store *targetdb.Store) *SARIFTool {
	return &SARIFTool{store: store}
}

func (t *SARIFTool) Name() string { return "report_sarif" }

func (t *SARIFTool) Description() string {
	return "Generate a SARIF 2.1.0 report from all findings"
}

func (t *SARIFTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"severity_filter": {"type": "string", "description": "Minimum severity to include (critical, high, medium, low, info)"},
			"host_filter": {"type": "string", "description": "Only include findings for this host"}
		}
	}`)
}

func (t *SARIFTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		SeverityFilter string `json:"severity_filter"`
		HostFilter     string `json:"host_filter"`
	}
	if len(params) > 0 {
		json.Unmarshal(params, &input)
	}

	findings := t.store.QueryFindings("", input.HostFilter, input.SeverityFilter)

	data, err := report.GenerateSARIF(findings, "1.0.0")
	if err != nil {
		return errorResult("SARIF generation failed: " + err.Error())
	}

	return textResult(string(data))
}
