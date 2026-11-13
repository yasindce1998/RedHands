package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// CancelTool stops a running campaign. It delegates to the engine's
// campaign/cancel handler (CancelFromJSON).
type CancelTool struct {
	engine Engine
}

// NewCancel creates the campaign_cancel tool.
func NewCancel(engine Engine) *CancelTool {
	return &CancelTool{engine: engine}
}

func (t *CancelTool) Name() string { return "campaign_cancel" }

func (t *CancelTool) Description() string {
	return "Stop a running campaign: cancels its execution context so no further steps launch; already-running tool calls finish. " +
		"The persisted state is kept, so campaign_resume can continue the campaign from its last checkpoint. " +
		"Takes the workflow_id returned by campaign_start."
}

func (t *CancelTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"workflow_id": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Workflow id of the running campaign to cancel"
			}
		},
		"required": ["workflow_id"]
	}`)
}

func (t *CancelTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	workflowID, err := requireWorkflowID(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.CancelFromJSON(params)
	if err != nil {
		return errorResult(fmt.Sprintf("cancel workflow %s: %v", workflowID, err))
	}

	summary := fmt.Sprintf("Campaign %s cancelled.", workflowID)
	guidance := "State is preserved at the last checkpoint; campaign_resume continues it, campaign_status shows where it stopped."
	return renderResult(summary, guidance, data)
}
