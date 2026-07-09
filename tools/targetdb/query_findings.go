package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type QueryFindingsTool struct {
	store *targetdb.Store
}

func NewQueryFindingsTool(store *targetdb.Store) *QueryFindingsTool {
	return &QueryFindingsTool{store: store}
}

func (t *QueryFindingsTool) Name() string { return "targetdb_query_findings" }

func (t *QueryFindingsTool) Description() string {
	return "Query findings from the target database with optional filters"
}

func (t *QueryFindingsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {"type": "string", "description": "Filter by host"},
			"severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Filter by severity"},
			"tool": {"type": "string", "description": "Filter by tool name"}
		}
	}`)
}

func (t *QueryFindingsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Host     string `json:"host"`
		Severity string `json:"severity"`
		Tool     string `json:"tool"`
	}
	_ = json.Unmarshal(params, &input)

	findings := t.store.QueryFindings(input.Host, input.Severity, input.Tool)
	if len(findings) == 0 {
		return textResult("No findings match the query"), nil
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return errorResult(fmt.Sprintf("marshal error: %s", err)), nil
	}
	return textResult(fmt.Sprintf("Found %d findings:\n%s", len(findings), string(data))), nil
}
