package targetdb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type AddCredTool struct {
	store *targetdb.Store
}

func NewAddCredTool(store *targetdb.Store) *AddCredTool {
	return &AddCredTool{store: store}
}

func (t *AddCredTool) Name() string { return "targetdb_add_cred" }

func (t *AddCredTool) Description() string {
	return "Add a credential to the target database"
}

func (t *AddCredTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {"type": "string", "description": "Associated host"},
			"username": {"type": "string", "description": "Username"},
			"secret": {"type": "string", "description": "Password, hash, or key"},
			"type": {"type": "string", "enum": ["password", "ntlm", "kerberos", "ssh_key", "token"], "description": "Credential type"},
			"domain": {"type": "string", "description": "Domain (for AD credentials)"},
			"source": {"type": "string", "description": "Tool that discovered this credential"},
			"valid": {"type": "boolean", "description": "Whether credential has been validated"}
		},
		"required": ["username", "secret", "type", "source"]
	}`)
}

func (t *AddCredTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Host     string `json:"host"`
		Username string `json:"username"`
		Secret   string `json:"secret"`
		Type     string `json:"type"`
		Domain   string `json:"domain"`
		Source   string `json:"source"`
		Valid    bool   `json:"valid"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult(fmt.Sprintf("invalid params: %s", err)), nil
	}
	if input.Username == "" || input.Secret == "" || input.Type == "" || input.Source == "" {
		return errorResult("username, secret, type, and source are required"), nil
	}

	cred := &targetdb.Credential{
		Host:     input.Host,
		Username: input.Username,
		Secret:   input.Secret,
		Type:     input.Type,
		Domain:   input.Domain,
		Source:   input.Source,
		Valid:    input.Valid,
	}
	t.store.AddCredential(cred)

	display := input.Username
	if input.Domain != "" {
		display = input.Domain + "\\" + input.Username
	}
	return textResult(fmt.Sprintf("Credential added: %s (%s) from %s", display, input.Type, input.Source)), nil
}
