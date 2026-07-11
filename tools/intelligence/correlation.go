package intelligence

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/correlation"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

// CorrelationTool analyzes findings for correlated attack patterns.
type CorrelationTool struct {
	store *targetdb.Store
}

func NewCorrelationTool(store *targetdb.Store) *CorrelationTool {
	return &CorrelationTool{store: store}
}

func (t *CorrelationTool) Name() string { return "correlation_analyze" }

func (t *CorrelationTool) Description() string {
	return "Analyze target database for correlated findings, escalation chains, and lateral movement opportunities"
}

func (t *CorrelationTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"filter_type": {
				"type": "string",
				"description": "Optional: filter results by type (escalation_chain, lateral_movement, high_risk_exposure, credential_reuse)",
				"enum": ["escalation_chain", "lateral_movement", "high_risk_exposure", "credential_reuse"]
			},
			"min_severity": {
				"type": "string",
				"description": "Minimum severity to include",
				"enum": ["info", "low", "medium", "high", "critical"]
			}
		}
	}`)
}

func (t *CorrelationTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		FilterType  string `json:"filter_type"`
		MinSeverity string `json:"min_severity"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &input)
	}

	engine := correlation.NewEngine(t.store)
	insights := engine.Analyze()

	if input.FilterType != "" {
		var filtered []correlation.Insight
		for _, i := range insights {
			if i.Type == input.FilterType {
				filtered = append(filtered, i)
			}
		}
		insights = filtered
	}

	if input.MinSeverity != "" {
		minRank := sevRank(input.MinSeverity)
		var filtered []correlation.Insight
		for _, i := range insights {
			if sevRank(i.Severity) >= minRank {
				filtered = append(filtered, i)
			}
		}
		insights = filtered
	}

	if len(insights) == 0 {
		return textResult("No correlated findings detected")
	}

	return jsonResult(insights)
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
