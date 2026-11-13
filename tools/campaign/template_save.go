package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// TemplateSaveTool persists a campaign playbook template. It delegates to
// the engine's campaign/template/save handler (SaveTemplateFromJSON).
type TemplateSaveTool struct {
	engine Engine
}

// NewTemplateSave creates the campaign_template_save tool.
func NewTemplateSave(engine Engine) *TemplateSaveTool {
	return &TemplateSaveTool{engine: engine}
}

func (t *TemplateSaveTool) Name() string { return "campaign_template_save" }

func (t *TemplateSaveTool) Description() string {
	return "Persist a campaign playbook template for reuse via campaign_start {\"template\": name, \"vars\": {...}}. " +
		"The template object is passed through to the engine, which validates it strictly (DisallowUnknownFields) and rejects unknown " +
		"top-level and step fields: steps are checked for valid record rules (type/path/fields), well-formed MITRE technique IDs " +
		"(e.g. T1613, T1552.007), on_fail policies (stop, continue, goto:<step_id>), and condition operators. " +
		"Fields: name (required, 1-64 chars of letters/digits/underscore/dash), description, vars (declared variables with optional " +
		"defaults), steps (the campaign steps). Overwrites an existing template with the same name."
}

func (t *TemplateSaveTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"description": "Playbook template object; the engine validates it strictly and rejects unknown fields",
		"properties": {
			"name": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Template name; overwrites an existing template with the same name"
			},
			"description": {
				"type": "string",
				"description": "What the playbook does"
			},
			"vars": {
				"type": "array",
				"description": "Variables the template expects",
				"items": {
					"type": "object",
					"properties": {
						"name": { "type": "string" },
						"description": { "type": "string" },
						"default": { "type": "string" },
						"required": { "type": "boolean" }
					},
					"required": ["name"]
				}
			},
			"steps": {
				"type": "array",
				"minItems": 1,
				"maxItems": 128,
				"description": "Campaign steps; same step schema as campaign_start"
			}
		},
		"required": ["name", "steps"]
	}`)
}

func (t *TemplateSaveTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	if err := requireObject(params); err != nil {
		return errorResult(err.Error())
	}
	name, err := requireName(params)
	if err != nil {
		return errorResult(err.Error())
	}

	data, err := t.engine.SaveTemplateFromJSON(params)
	if err != nil {
		return errorResult(fmt.Sprintf("save template %s: %v", name, err))
	}

	summary := fmt.Sprintf("Playbook template %q saved.", name)
	guidance := fmt.Sprintf("Run it with campaign_start {\"template\": %q, \"vars\": {...}}; inspect it with campaign_template_get.", name)
	return renderResult(summary, guidance, data)
}
