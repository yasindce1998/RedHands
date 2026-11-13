package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// TemplatesTool lists saved campaign playbook templates. It delegates to
// the engine's campaign/templates handler (TemplatesFromJSON).
type TemplatesTool struct {
	engine Engine
}

// NewTemplates creates the campaign_templates tool.
func NewTemplates(engine Engine) *TemplatesTool {
	return &TemplatesTool{engine: engine}
}

func (t *TemplatesTool) Name() string { return "campaign_templates" }

func (t *TemplatesTool) Description() string {
	return "Read-only: list the saved campaign playbook templates, each with its name, description, expected vars, and step summary. " +
		"No parameters. No side effects — nothing is executed; run a playbook with campaign_start (template + vars), " +
		"inspect one in full with campaign_template_get, persist new ones with campaign_template_save."
}

func (t *TemplatesTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {},
		"additionalProperties": false
	}`)
}

func (t *TemplatesTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	normalized, err := normalizeObject(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.TemplatesFromJSON(normalized)
	if err != nil {
		return errorResult("list templates: " + err.Error())
	}

	summary := fmt.Sprintf("%d playbook template(s) available.", countTopLevel(data))
	guidance := "Fetch one with campaign_template_get (name), run it with campaign_start {\"template\": name, \"vars\": {...}}."
	return renderResult(summary, guidance, data)
}
