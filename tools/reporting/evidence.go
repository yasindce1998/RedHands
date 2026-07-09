package reporting

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type EvidenceListTool struct {
	store *evidence.Store
}

func NewEvidenceListTool(store *evidence.Store) *EvidenceListTool {
	return &EvidenceListTool{store: store}
}

func (t *EvidenceListTool) Name() string { return "evidence_list" }

func (t *EvidenceListTool) Description() string {
	return "List all captured evidence items"
}

func (t *EvidenceListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"tool": {"type": "string", "description": "Filter by tool name"},
			"host": {"type": "string", "description": "Filter by host"}
		}
	}`)
}

func (t *EvidenceListTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	}
	if len(params) > 0 {
		json.Unmarshal(params, &input)
	}

	var items []*evidence.Item
	switch {
	case input.Tool != "":
		items = t.store.ListByTool(input.Tool)
	case input.Host != "":
		items = t.store.ListByHost(input.Host)
	default:
		items = t.store.List()
	}

	if len(items) == 0 {
		return textResult("No evidence items found")
	}
	return jsonResult(items)
}

type EvidenceScreenshotTool struct {
	store *evidence.Store
}

func NewEvidenceScreenshotTool(store *evidence.Store) *EvidenceScreenshotTool {
	return &EvidenceScreenshotTool{store: store}
}

func (t *EvidenceScreenshotTool) Name() string { return "evidence_screenshot" }

func (t *EvidenceScreenshotTool) Description() string {
	return "Take a screenshot of a URL for evidence"
}

func (t *EvidenceScreenshotTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {"type": "string", "description": "URL to screenshot"}
		},
		"required": ["url"]
	}`)
}

func (t *EvidenceScreenshotTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}
	if input.URL == "" {
		return errorResult("url is required")
	}

	item, err := t.store.Screenshot(ctx, input.URL)
	if err != nil {
		return errorResult("screenshot failed: " + err.Error())
	}

	return jsonResult(item)
}
