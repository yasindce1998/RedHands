package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type AddHostTool struct {
	store *targetdb.Store
}

func NewAddHostTool(store *targetdb.Store) *AddHostTool {
	return &AddHostTool{store: store}
}

func (t *AddHostTool) Name() string { return "targetdb_add_host" }

func (t *AddHostTool) Description() string {
	return "Add or update a host in the target database"
}

func (t *AddHostTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"ip": {"type": "string", "description": "IP address of the host"},
			"hostname": {"type": "string", "description": "Hostname (optional)"},
			"os": {"type": "string", "description": "Operating system (optional)"},
			"tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"}
		},
		"required": ["ip"]
	}`)
}

func (t *AddHostTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		IP       string   `json:"ip"`
		Hostname string   `json:"hostname"`
		OS       string   `json:"os"`
		Tags     []string `json:"tags"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult(fmt.Sprintf("invalid params: %s", err)), nil
	}
	if input.IP == "" {
		return errorResult("ip is required"), nil
	}

	host := &targetdb.Host{
		IP:       input.IP,
		Hostname: input.Hostname,
		OS:       input.OS,
		Tags:     input.Tags,
	}
	t.store.AddHost(host)

	return textResult(fmt.Sprintf("Host %s added/updated in target database", input.IP)), nil
}
