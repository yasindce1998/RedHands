package aegis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// AlertsParseTool parses NDJSON alert files produced by the Aegis-Shadow
// defense daemon. Pure file reading; no binary is executed.
type AlertsParseTool struct{}

// NewAlertsParse constructs the aegis_alerts_parse tool.
func NewAlertsParse() *AlertsParseTool { return &AlertsParseTool{} }

func (t *AlertsParseTool) Name() string { return "aegis_alerts_parse" }

func (t *AlertsParseTool) Description() string {
	return "Parse an NDJSON alert file produced by `defense -o <file>` (or `defense --json-stdout` redirected to a file) and return a summary plus matching alerts, optionally filtered by minimum severity (LOW/MEDIUM/HIGH/CRITICAL), attack-chain membership, and minimum anomaly score. Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Read-only file analysis; never executes any binary."
}

func (t *AlertsParseTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to the NDJSON alert file written by the defense daemon"
			},
			"severity": {
				"type": "string",
				"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
				"description": "Only return alerts at or above this severity"
			},
			"only_attack_chains": {
				"type": "boolean",
				"description": "Only return alerts flagged as part of an attack chain (default: false)"
			},
			"min_anomaly_score": {
				"type": "number",
				"description": "Only return alerts with anomaly_score at or above this value (default: no floor)"
			}
		},
		"required": ["file"]
	}`)
}

func (t *AlertsParseTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		File             string  `json:"file"`
		Severity         string  `json:"severity"`
		OnlyAttackChains bool    `json:"only_attack_chains"`
		MinAnomalyScore  float64 `json:"min_anomaly_score"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateExistingFile(input.File, "file", maxAlertFileSize); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSeverity(input.Severity); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.MinAnomalyScore < 0 {
		return errorResult("min_anomaly_score must be >= 0"), nil
	}

	alerts, malformed, err := parseAlertsFile(input.File)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	f := alertFilter{
		minSeverity: input.Severity,
		onlyChains:  input.OnlyAttackChains,
		minAnomaly:  input.MinAnomalyScore,
	}
	matching := filterAlerts(alerts, f)

	var filters []string
	if input.Severity != "" {
		filters = append(filters, "severity >= "+input.Severity)
	}
	if input.OnlyAttackChains {
		filters = append(filters, "attack chains only")
	}
	if input.MinAnomalyScore > 0 {
		filters = append(filters, fmt.Sprintf("anomaly_score >= %.2f", input.MinAnomalyScore))
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderAlertsReport(alertsReport{
			file:      input.File,
			total:     len(alerts),
			malformed: malformed,
			matching:  matching,
			filters:   filters,
			limit:     alertDisplayLimit,
		})}},
	}, nil
}
