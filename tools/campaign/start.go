package campaign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// StartTool launches a multi-step campaign. It delegates to the engine's
// campaign/run handler (RunFromJSON) and surfaces the workflow_id in the
// first line of the result so agents can poll it.
type StartTool struct {
	engine Engine
}

// NewStart creates the campaign_start tool.
func NewStart(engine Engine) *StartTool {
	return &StartTool{engine: engine}
}

func (t *StartTool) Name() string { return "campaign_start" }

func (t *StartTool) Description() string {
	return "DESTRUCTIVE: launch a multi-step RedHands campaign that chains real tools — this executes the tools named in each step. " +
		"Provide either a steps array or a saved playbook template plus vars. Each step: tool (RedHands tool name), params (JSON object, " +
		"$prev.json.* paths reference the previous step's result), optional id, condition (gate on a prior step's output; ops: contains, " +
		"not_contains, equals, not_equals, success, failure, json_exists, json_not_exists, json_equals, json_not_equals, json_contains, " +
		"json_gt, json_lt), on_fail (stop, continue, or goto:<step_id> for recovery loops), parallel (up to 16 sub-steps run concurrently), " +
		"record rules (persist hosts/services/credentials/findings to the target DB), and mitre ATT&CK technique IDs (e.g. T1613, T1552.007). " +
		"Optional top-level: id (custom workflow id), name, engagement (binds the run to a named engagement that must be active — every " +
		"step's scope checks run against it). Every step executes through the full server middleware chain (audit, auth, rate limits, " +
		"scope, dry-run, approval) exactly like a direct tool call. The result's first line states the workflow_id: poll progress with " +
		"campaign_status, resume paused or cancelled runs with campaign_resume, stop with campaign_cancel. Unknown fields are rejected."
}

func (t *StartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"description": "Campaign request: steps (inline) or template+vars (saved playbook). The engine validates strictly and rejects unknown top-level and step fields.",
		"properties": {
			"id": {
				"type": "string",
				"pattern": "^[A-Za-z0-9_-]{1,64}$",
				"description": "Optional custom workflow id; one is generated when omitted"
			},
			"name": {
				"type": "string",
				"description": "Optional human-readable campaign name"
			},
			"steps": {
				"type": "array",
				"minItems": 1,
				"maxItems": 128,
				"description": "Ordered campaign steps; alternative to template",
				"items": {
					"type": "object",
					"properties": {
						"id": {
							"type": "string",
							"description": "Step identifier for conditions, goto recovery, and result references"
						},
						"tool": {
							"type": "string",
							"description": "RedHands tool name to execute"
						},
						"params": {
							"type": "object",
							"description": "Arguments passed to the tool; $prev.json.* paths substitute values from the previous step's result"
						},
						"parallel": {
							"type": "array",
							"maxItems": 16,
							"description": "Sub-steps executed concurrently; each has the same shape as a regular step; the group succeeds when all sub-steps succeed (subject to on_fail)",
							"items": { "type": "object" }
						},
						"condition": {
							"type": "object",
							"description": "Skip the step unless the condition holds on a prior step's result",
							"properties": {
								"step": {
									"type": "string",
									"description": "Step ID, $prev for the immediately preceding step, or a zero-based index as a string"
								},
								"op": {
									"type": "string",
									"enum": ["contains", "not_contains", "equals", "not_equals", "success", "failure", "json_exists", "json_not_exists", "json_equals", "json_not_equals", "json_contains", "json_gt", "json_lt"]
								},
								"value": {
									"type": "string",
									"description": "Value compared by the comparison operators"
								},
								"path": {
									"type": "string",
									"description": "Dot-separated JSON path (e.g. hosts.0.ip) used by the json_* operators"
								}
							},
							"required": ["op"]
						},
						"on_fail": {
							"type": "string",
							"description": "Failure policy: stop (default), continue, or goto:<step_id> to jump to a recovery step"
						},
						"record": {
							"type": "array",
							"description": "Rules that extract structured items from this step's output into the target database",
							"items": {
								"type": "object",
								"properties": {
									"type": {
										"type": "string",
										"enum": ["host", "service", "credential", "finding"]
									},
									"path": {
										"type": "string",
										"description": "Dot-separated JSON path to an array of objects in the step result (e.g. hosts)"
									},
									"fields": {
										"type": "object",
										"additionalProperties": { "type": "string" },
										"description": "Target DB field name to relative JSON path within each array element"
									}
								},
								"required": ["type", "path", "fields"]
							}
						},
						"mitre": {
							"type": "array",
							"description": "ATT&CK technique IDs implemented by this step",
							"items": { "type": "string", "pattern": "^[Tt][0-9]{4}(\\.[0-9]{3})?$" }
						}
					},
					"required": ["tool"]
				}
			},
			"template": {
				"type": "string",
				"description": "Saved playbook template name (see campaign_templates); alternative to steps"
			},
			"vars": {
				"type": "object",
				"additionalProperties": { "type": "string" },
				"description": "Variable substitutions for the template's $var placeholders"
			},
			"engagement": {
				"type": "string",
				"description": "Optional engagement name to bind the campaign to; it must exist and be the active engagement"
			}
		}
	}`)
}

func (t *StartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	if err := requireObject(params); err != nil {
		return errorResult(err.Error())
	}
	// Validate the optional custom workflow id locally (mirrors the engine's
	// ValidWorkflowID) so malformed ids fail before any step executes.
	if id := resultField(params, "id"); id != "" && !validID(id) {
		return errorResult("id " + idRule)
	}

	data, err := t.engine.RunFromJSON(ctx, params)
	if err != nil {
		return errorResult("campaign failed to start: " + err.Error())
	}

	id := resultField(data, "workflow_id")
	status := resultField(data, "status")
	summary := "Campaign started (no workflow_id in result)."
	if id != "" {
		summary = fmt.Sprintf("Campaign %s — %s.", id, status)
	}
	guidance := "Poll progress with campaign_status; resume a paused or cancelled run with campaign_resume; stop a running one with campaign_cancel."
	if id != "" {
		guidance = fmt.Sprintf("Poll progress with campaign_status (workflow_id %q); resume a paused or cancelled run with campaign_resume; stop a running one with campaign_cancel.", id)
	}
	return renderResult(summary, guidance, data)
}
