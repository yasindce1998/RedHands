package intelligence

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/riskscore"
)

// RiskScoreTool calculates risk scores for findings.
type RiskScoreTool struct{}

func NewRiskScoreTool() *RiskScoreTool {
	return &RiskScoreTool{}
}

func (t *RiskScoreTool) Name() string { return "risk_score_calculate" }

func (t *RiskScoreTool) Cacheable() bool { return true }

func (t *RiskScoreTool) Description() string {
	return "Calculate a risk score from exploitability, impact, and exposure values (0-10 scale)"
}

func (t *RiskScoreTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"exploitability": {"type": "number", "description": "Exploitability score (0-10)"},
			"impact": {"type": "number", "description": "Impact score (0-10)"},
			"exposure": {"type": "number", "description": "Exposure score (0-10)"},
			"severity": {"type": "string", "description": "Alternative: use severity string instead of numeric values", "enum": ["info", "low", "medium", "high", "critical"]},
			"has_exploit": {"type": "boolean", "description": "Whether a public exploit exists (used with severity mode)"},
			"is_exposed": {"type": "boolean", "description": "Whether the target is internet-exposed (used with severity mode)"}
		}
	}`)
}

func (t *RiskScoreTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Exploitability float64 `json:"exploitability"`
		Impact         float64 `json:"impact"`
		Exposure       float64 `json:"exposure"`
		Severity       string  `json:"severity"`
		HasExploit     bool    `json:"has_exploit"`
		IsExposed      bool    `json:"is_exposed"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	var score riskscore.Score
	if input.Severity != "" {
		score = riskscore.FromSeverity(input.Severity, input.HasExploit, input.IsExposed)
	} else {
		score = riskscore.Calculate(riskscore.Params{
			Exploitability: input.Exploitability,
			Impact:         input.Impact,
			Exposure:       input.Exposure,
		})
	}

	return jsonResult(score)
}
