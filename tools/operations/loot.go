package operations

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/loot"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type LootAddTool struct {
	store *loot.Store
}

func NewLootAddTool(store *loot.Store) *LootAddTool {
	return &LootAddTool{store: store}
}

func (t *LootAddTool) Name() string { return "loot_add" }

func (t *LootAddTool) Description() string {
	return "Add a captured artifact (file, hash, ticket, token) to the loot store"
}

func (t *LootAddTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"type": {"type": "string", "description": "Loot type (file, hash, ticket, token, key, screenshot)"},
			"host": {"type": "string", "description": "Source host"},
			"description": {"type": "string", "description": "Description of the loot"},
			"data": {"type": "string", "description": "Loot content or file path"},
			"tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"}
		},
		"required": ["type", "description"]
	}`)
}

func (t *LootAddTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Type        string   `json:"type"`
		Host        string   `json:"host"`
		Description string   `json:"description"`
		Data        string   `json:"data"`
		Tags        []string `json:"tags"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	t.store.Add(&loot.Item{
		Type:        input.Type,
		Host:        input.Host,
		Description: input.Description,
		Data:        input.Data,
		Tags:        input.Tags,
	})

	return textResult("Loot added successfully")
}

type LootListTool struct {
	store *loot.Store
}

func NewLootListTool(store *loot.Store) *LootListTool {
	return &LootListTool{store: store}
}

func (t *LootListTool) Name() string { return "loot_list" }

func (t *LootListTool) Description() string {
	return "List captured loot, optionally filtered by type or host"
}

func (t *LootListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"type": {"type": "string", "description": "Filter by loot type"},
			"host": {"type": "string", "description": "Filter by source host"}
		}
	}`)
}

func (t *LootListTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Type string `json:"type"`
		Host string `json:"host"`
	}
	if len(params) > 0 {
		json.Unmarshal(params, &input)
	}

	items := t.store.List(input.Type, input.Host)
	if len(items) == 0 {
		return textResult("No loot found")
	}
	return jsonResult(items)
}

type LootSearchTool struct {
	store *loot.Store
}

func NewLootSearchTool(store *loot.Store) *LootSearchTool {
	return &LootSearchTool{store: store}
}

func (t *LootSearchTool) Name() string { return "loot_search" }

func (t *LootSearchTool) Description() string {
	return "Search loot by keyword"
}

func (t *LootSearchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": {"type": "string", "description": "Search query"}
		},
		"required": ["query"]
	}`)
}

func (t *LootSearchTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}
	if input.Query == "" {
		return errorResult("query is required")
	}

	items := t.store.Search(input.Query)
	if len(items) == 0 {
		return textResult("No results found")
	}
	return jsonResult(items)
}
