package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type ListHostsTool struct {
	store *targetdb.Store
}

func NewListHostsTool(store *targetdb.Store) *ListHostsTool {
	return &ListHostsTool{store: store}
}

func (t *ListHostsTool) Name() string { return "targetdb_list_hosts" }

func (t *ListHostsTool) Description() string {
	return "List all hosts in the target database"
}

func (t *ListHostsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"tag": {"type": "string", "description": "Filter by tag (optional)"}
		}
	}`)
}

func (t *ListHostsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Tag string `json:"tag"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &input); err != nil {
			return errorResult(fmt.Sprintf("invalid params: %s", err)), nil
		}
	}

	hosts := t.store.ListHosts()

	if input.Tag != "" {
		var filtered []*targetdb.Host
		for _, h := range hosts {
			for _, tag := range h.Tags {
				if tag == input.Tag {
					filtered = append(filtered, h)
					break
				}
			}
		}
		hosts = filtered
	}

	if len(hosts) == 0 {
		return textResult("No hosts found in target database"), nil
	}

	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return errorResult(fmt.Sprintf("marshal error: %s", err)), nil
	}
	return textResult(fmt.Sprintf("Found %d hosts:\n%s", len(hosts), string(data))), nil
}
