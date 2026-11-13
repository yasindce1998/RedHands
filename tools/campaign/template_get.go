package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// TemplateGetTool fetches one saved playbook template. It delegates to the
// engine's campaign/template/get handler (GetTemplateFromJSON).
type TemplateGetTool struct {
	engine Engine
}

// NewTemplateGet creates the campaign_template_get tool.
func NewTemplateGet(engine Engine) *TemplateGetTool {
	return &TemplateGetTool{engine: engine}
}

func (t *TemplateGetTool) Name() string { return "campaign_template_get" }

func (t *TemplateGetTool) Description() string {
	return "Read-only: fetch one saved campaign playbook template by name — its description, declared vars, and the full steps array " +
		"(tools, params, conditions, on_fail, record rules, MITRE IDs). No side effects — nothing is executed; run the playbook with " +
		"campaign_start {\"template\": name, \"vars\": {...}}. List available names with campaign_templates."
}

func (t *TemplateGetTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Template name (see campaign_templates)"
			}
		},
		"required": ["name"]
	}`)
}

func (t *TemplateGetTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	name, err := requireName(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.GetTemplateFromJSON(params)
	if err != nil {
		return errorResult(fmt.Sprintf("get template %s: %v", name, err))
	}

	summary := fmt.Sprintf("Playbook template %q:", name)
	guidance := fmt.Sprintf("Run it with campaign_start {\"template\": %q, \"vars\": {...}} — vars must cover the template's declared variables.", name)
	return renderResult(summary, guidance, data)
}
