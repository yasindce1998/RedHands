package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ListTool lists every tracked campaign. It delegates to the engine's
// campaign/list handler (ListFromJSON).
type ListTool struct {
	engine Engine
}

// NewList creates the campaign_list tool.
func NewList(engine Engine) *ListTool {
	return &ListTool{engine: engine}
}

func (t *ListTool) Name() string { return "campaign_list" }

func (t *ListTool) Description() string {
	return "Read-only: list every tracked campaign with its workflow_id, name, status, engagement, step count, and creation time. " +
		"No parameters. No side effects — this only reads persisted workflow state; use campaign_status for one campaign's full detail."
}

func (t *ListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {},
		"additionalProperties": false
	}`)
}

func (t *ListTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	normalized, err := normalizeObject(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.ListFromJSON(normalized)
	if err != nil {
		return errorResult("list campaigns: " + err.Error())
	}

	summary := fmt.Sprintf("%d campaign(s) tracked.", countTopLevel(data))
	guidance := "Fetch one campaign's full state with campaign_status (workflow_id), control runs with campaign_resume and campaign_cancel."
	return renderResult(summary, guidance, data)
}

// countTopLevel counts the elements of a top-level JSON array, returning 0
// for anything else.
func countTopLevel(data json.RawMessage) int {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return 0
	}
	return len(arr)
}
