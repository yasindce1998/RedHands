package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type ListCredsTool struct {
	store *targetdb.Store
}

func NewListCredsTool(store *targetdb.Store) *ListCredsTool {
	return &ListCredsTool{store: store}
}

func (t *ListCredsTool) Name() string { return "targetdb_list_creds" }

func (t *ListCredsTool) Description() string {
	return "List all credentials in the target database"
}

func (t *ListCredsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {"type": "string", "description": "Filter by host (optional)"},
			"type": {"type": "string", "description": "Filter by credential type (optional)"},
			"valid_only": {"type": "boolean", "description": "Only show validated credentials"}
		}
	}`)
}

func (t *ListCredsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Host      string `json:"host"`
		Type      string `json:"type"`
		ValidOnly bool   `json:"valid_only"`
	}
	_ = json.Unmarshal(params, &input)

	creds := t.store.ListCredentials()

	var filtered []*targetdb.Credential
	for _, c := range creds {
		if input.Host != "" && c.Host != input.Host {
			continue
		}
		if input.Type != "" && c.Type != input.Type {
			continue
		}
		if input.ValidOnly && !c.Valid {
			continue
		}
		filtered = append(filtered, c)
	}

	if len(filtered) == 0 {
		return textResult("No credentials found"), nil
	}

	data, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return errorResult(fmt.Sprintf("marshal error: %s", err)), nil
	}
	return textResult(fmt.Sprintf("Found %d credentials:\n%s", len(filtered), string(data))), nil
}
