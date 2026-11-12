package aegis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

const (
	// defaultTailCount is the number of alerts aegis_alerts_tail returns when
	// no count is supplied.
	defaultTailCount = 20
	// maxTailCount caps the tail window.
	maxTailCount = 500
)

// AlertsTailTool returns the last N alerts from an NDJSON alert file.
// Pure file reading; no binary is executed.
type AlertsTailTool struct{}

// NewAlertsTail constructs the aegis_alerts_tail tool.
func NewAlertsTail() *AlertsTailTool { return &AlertsTailTool{} }

func (t *AlertsTailTool) Name() string { return "aegis_alerts_tail" }

func (t *AlertsTailTool) Description() string {
	return "Return the last N alerts from an NDJSON alert file produced by `defense -o <file>`, optionally filtered by minimum severity (LOW/MEDIUM/HIGH/CRITICAL). Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Read-only file analysis; never executes any binary. Useful for checking what the defense daemon most recently emitted in your lab VM."
}

func (t *AlertsTailTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to the NDJSON alert file written by the defense daemon"
			},
			"count": {
				"type": "integer",
				"description": "Number of most recent alerts to return (default: 20, max: 500)"
			},
			"severity": {
				"type": "string",
				"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
				"description": "Only consider alerts at or above this severity"
			}
		},
		"required": ["file"]
	}`)
}

func (t *AlertsTailTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		File     string `json:"file"`
		Count    int    `json:"count"`
		Severity string `json:"severity"`
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
	count := input.Count
	if count == 0 {
		count = defaultTailCount
	}
	if count < 0 {
		return errorResult("count must be a positive integer"), nil
	}
	if count > maxTailCount {
		return errorResult(fmt.Sprintf("count must be at most %d", maxTailCount)), nil
	}

	alerts, malformed, err := parseAlertsFile(input.File)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	severityMatches := filterAlerts(alerts, alertFilter{minSeverity: input.Severity})
	matching := severityMatches
	scopeNote := ""
	if len(severityMatches) > count {
		matching = severityMatches[len(severityMatches)-count:]
		scopeNote = fmt.Sprintf("last %d of %d severity-matching alerts", count, len(severityMatches))
	}

	var filters []string
	if input.Severity != "" {
		filters = append(filters, "severity >= "+input.Severity)
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderAlertsReport(alertsReport{
			file:      input.File,
			total:     len(alerts),
			malformed: malformed,
			matching:  matching,
			filters:   filters,
			scopeNote: scopeNote,
		})}},
	}, nil
}
