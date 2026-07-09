package operations

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type EngagementCreateTool struct {
	mgr *engagement.Manager
}

func NewEngagementCreateTool(mgr *engagement.Manager) *EngagementCreateTool {
	return &EngagementCreateTool{mgr: mgr}
}

func (t *EngagementCreateTool) Name() string { return "engagement_create" }

func (t *EngagementCreateTool) Description() string {
	return "Create a new engagement with scope definition"
}

func (t *EngagementCreateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string", "description": "Engagement name"},
			"client": {"type": "string", "description": "Client name"},
			"scope": {"type": "array", "items": {"type": "string"}, "description": "In-scope targets (IPs, CIDRs, domains, wildcards)"}
		},
		"required": ["name", "scope"]
	}`)
}

func (t *EngagementCreateTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Name   string   `json:"name"`
		Client string   `json:"client"`
		Scope  []string `json:"scope"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}
	if input.Name == "" {
		return errorResult("name is required")
	}

	eng, err := t.mgr.Create(input.Name, input.Client, input.Scope)
	if err != nil {
		return errorResult(err.Error())
	}

	return jsonResult(eng)
}

type EngagementSwitchTool struct {
	mgr *engagement.Manager
}

func NewEngagementSwitchTool(mgr *engagement.Manager) *EngagementSwitchTool {
	return &EngagementSwitchTool{mgr: mgr}
}

func (t *EngagementSwitchTool) Name() string { return "engagement_switch" }

func (t *EngagementSwitchTool) Description() string {
	return "Switch to a different engagement"
}

func (t *EngagementSwitchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"id": {"type": "string", "description": "Engagement ID to switch to"}
		},
		"required": ["id"]
	}`)
}

func (t *EngagementSwitchTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	if err := t.mgr.Switch(input.ID); err != nil {
		return errorResult(err.Error())
	}

	return textResult("Switched to engagement: " + input.ID)
}

type EngagementListTool struct {
	mgr *engagement.Manager
}

func NewEngagementListTool(mgr *engagement.Manager) *EngagementListTool {
	return &EngagementListTool{mgr: mgr}
}

func (t *EngagementListTool) Name() string { return "engagement_list" }

func (t *EngagementListTool) Description() string {
	return "List all engagements"
}

func (t *EngagementListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type": "object", "properties": {}}`)
}

func (t *EngagementListTool) Execute(_ context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	engagements := t.mgr.List()
	active := t.mgr.Active()

	type engDisplay struct {
		*engagement.Engagement
		Active bool `json:"active"`
	}

	var result []engDisplay
	for _, e := range engagements {
		isActive := active != nil && e.ID == active.ID
		result = append(result, engDisplay{e, isActive})
	}

	return jsonResult(result)
}
