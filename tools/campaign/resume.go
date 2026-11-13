package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ResumeTool continues a paused or cancelled campaign from its last
// checkpoint. It delegates to the engine's campaign/resume handler
// (ResumeFromJSON).
type ResumeTool struct {
	engine Engine
}

// NewResume creates the campaign_resume tool.
func NewResume(engine Engine) *ResumeTool {
	return &ResumeTool{engine: engine}
}

func (t *ResumeTool) Name() string { return "campaign_resume" }

func (t *ResumeTool) Description() string {
	return "Resume a paused or cancelled campaign from its last checkpoint: DESTRUCTIVE — the remaining steps execute real tools through the " +
		"full server middleware chain. The workflow's engagement binding is re-validated on resume. Takes the workflow_id returned by " +
		"campaign_start; find candidates with campaign_list or campaign_status."
}

func (t *ResumeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"workflow_id": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Workflow id of the paused or cancelled campaign to resume"
			}
		},
		"required": ["workflow_id"]
	}`)
}

func (t *ResumeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	workflowID, err := requireWorkflowID(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.ResumeFromJSON(ctx, params)
	if err != nil {
		return errorResult(fmt.Sprintf("resume workflow %s: %v", workflowID, err))
	}

	summary := fmt.Sprintf("Campaign %s resumed.", workflowID)
	if status := resultField(data, "status"); status != "" {
		summary = fmt.Sprintf("Campaign %s resumed — %s.", workflowID, status)
	}
	guidance := fmt.Sprintf("Poll progress with campaign_status (workflow_id %q); stop the run with campaign_cancel.", workflowID)
	return renderResult(summary, guidance, data)
}
