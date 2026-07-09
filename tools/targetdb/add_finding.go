package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type AddFindingTool struct {
	store *targetdb.Store
}

func NewAddFindingTool(store *targetdb.Store) *AddFindingTool {
	return &AddFindingTool{store: store}
}

func (t *AddFindingTool) Name() string { return "targetdb_add_finding" }

func (t *AddFindingTool) Description() string {
	return "Add a security finding to the target database"
}

func (t *AddFindingTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {"type": "string", "description": "Target host IP or hostname"},
			"tool": {"type": "string", "description": "Tool that generated the finding"},
			"severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Finding severity"},
			"title": {"type": "string", "description": "Short title of the finding"},
			"description": {"type": "string", "description": "Detailed description"},
			"evidence": {"type": "string", "description": "Supporting evidence"},
			"mitre": {"type": "array", "items": {"type": "string"}, "description": "MITRE ATT&CK technique IDs"}
		},
		"required": ["host", "tool", "severity", "title"]
	}`)
}

func (t *AddFindingTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Host        string   `json:"host"`
		Tool        string   `json:"tool"`
		Severity    string   `json:"severity"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Evidence    string   `json:"evidence"`
		MITRE       []string `json:"mitre"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult(fmt.Sprintf("invalid params: %s", err)), nil
	}
	if input.Host == "" || input.Tool == "" || input.Severity == "" || input.Title == "" {
		return errorResult("host, tool, severity, and title are required"), nil
	}

	finding := &targetdb.Finding{
		Host:        input.Host,
		Tool:        input.Tool,
		Severity:    input.Severity,
		Title:       input.Title,
		Description: input.Description,
		Evidence:    input.Evidence,
		MITRE:       input.MITRE,
	}
	t.store.AddFinding(finding)

	return textResult(fmt.Sprintf("Finding added: [%s] %s on %s", input.Severity, input.Title, input.Host)), nil
}
