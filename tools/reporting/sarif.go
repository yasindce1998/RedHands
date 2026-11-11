package reporting

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/version"
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
		if err := json.Unmarshal(params, &input); err != nil {
			return errorResult("invalid params: " + err.Error())
		}
	}

	ranks := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	minimum, valid := ranks[input.SeverityFilter]
	if input.SeverityFilter != "" && !valid {
		return errorResult("invalid severity_filter")
	}
	findings := t.store.QueryFindings(input.HostFilter, "", "")
	if input.SeverityFilter != "" {
		filtered := make([]*targetdb.Finding, 0, len(findings))
		for _, finding := range findings {
			rank, ok := ranks[finding.Severity]
			if ok && rank >= minimum {
				filtered = append(filtered, finding)
			}
		}
		findings = filtered
	}

	data, err := report.GenerateSARIF(findings, version.Version)
	if err != nil {
		return errorResult("SARIF generation failed: " + err.Error())
	}

	return textResult(string(data))
}
