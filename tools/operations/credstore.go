package operations

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/credstore"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CredstoreAddTool struct {
	store *credstore.Store
}

func NewCredstoreAddTool(store *credstore.Store) *CredstoreAddTool {
	return &CredstoreAddTool{store: store}
}

func (t *CredstoreAddTool) Name() string { return "credstore_add" }

func (t *CredstoreAddTool) Description() string {
	return "Add a credential to the encrypted credential store"
}

func (t *CredstoreAddTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {"type": "string", "description": "Target host"},
			"username": {"type": "string", "description": "Username"},
			"secret": {"type": "string", "description": "Password, hash, or key"},
			"type": {"type": "string", "description": "Credential type (password, hash, key, ticket)", "enum": ["password", "hash", "key", "ticket"]},
			"domain": {"type": "string", "description": "Domain"},
			"source": {"type": "string", "description": "How this credential was obtained"},
			"valid": {"type": "boolean", "description": "Whether the credential has been verified"}
		},
		"required": ["username", "secret", "type"]
	}`)
}

func (t *CredstoreAddTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
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
		return errorResult("invalid params: " + err.Error())
	}

	t.store.Add(&credstore.Entry{
		Host:     input.Host,
		Username: input.Username,
		Secret:   input.Secret,
		Type:     input.Type,
		Domain:   input.Domain,
		Source:   input.Source,
		Valid:    input.Valid,
	})

	return textResult(fmt.Sprintf("Credential stored: %s@%s (%s)", input.Username, input.Host, input.Type))
}

type CredstoreSearchTool struct {
	store *credstore.Store
}

func NewCredstoreSearchTool(store *credstore.Store) *CredstoreSearchTool {
	return &CredstoreSearchTool{store: store}
}

func (t *CredstoreSearchTool) Name() string { return "credstore_search" }

func (t *CredstoreSearchTool) Description() string {
	return "Search the credential store by host, username, or domain"
}

func (t *CredstoreSearchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": {"type": "string", "description": "Search query (matches host, username, domain)"},
			"valid_only": {"type": "boolean", "description": "Only return verified credentials"}
		},
		"required": ["query"]
	}`)
}

func (t *CredstoreSearchTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Query     string `json:"query"`
		ValidOnly bool   `json:"valid_only"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	var results []*credstore.Entry
	if input.ValidOnly {
		results = t.store.ValidOnly()
	} else {
		results = t.store.Search(input.Query)
	}

	if len(results) == 0 {
		return textResult("No credentials found")
	}

	// Redact secrets in output
	type safeEntry struct {
		ID       string `json:"id"`
		Host     string `json:"host"`
		Username string `json:"username"`
		Type     string `json:"type"`
		Domain   string `json:"domain,omitempty"`
		Source   string `json:"source"`
		Valid    bool   `json:"valid"`
	}

	var safe []safeEntry
	for _, e := range results {
		safe = append(safe, safeEntry{
			ID:       e.ID,
			Host:     e.Host,
			Username: e.Username,
			Type:     e.Type,
			Domain:   e.Domain,
			Source:   e.Source,
			Valid:    e.Valid,
		})
	}

	return jsonResult(safe)
}
