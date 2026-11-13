package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// StatusTool fetches the persisted state of a campaign. It delegates to the
// engine's campaign/status handler (StatusFromJSON).
type StatusTool struct {
	engine Engine
}

// NewStatus creates the campaign_status tool.
func NewStatus(engine Engine) *StatusTool {
	return &StatusTool{engine: engine}
}

func (t *StatusTool) Name() string { return "campaign_status" }

func (t *StatusTool) Description() string {
	return "Read-only: fetch the persisted state of one campaign by workflow_id — status (running, paused, cancelled, completed, failed), " +
		"per-step results, next step index, error, engagement binding, and recorded MITRE techniques. Use the workflow_id returned by " +
		"campaign_start. No side effects: nothing is executed, resumed, or modified."
}

func (t *StatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"workflow_id": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Workflow id returned by campaign_start"
			}
		},
		"required": ["workflow_id"]
	}`)
}

func (t *StatusTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	workflowID, err := requireWorkflowID(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.StatusFromJSON(params)
	if err != nil {
		return errorResult(fmt.Sprintf("status for workflow %s: %v", workflowID, err))
	}

	summary := fmt.Sprintf("Campaign %s status:", workflowID)
	if id := resultField(data, "workflow_id"); id != "" {
		if status := resultField(data, "status"); status != "" {
			summary = fmt.Sprintf("Campaign %s is %s.", id, status)
		}
	}
	guidance := "Resume a paused or cancelled run with campaign_resume; stop a running one with campaign_cancel; list every campaign with campaign_list."
	return renderResult(summary, guidance, data)
}
