package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type KeyringInput struct {
	Action   string `json:"action"`
	KeyID    string `json:"key_id,omitempty"`
	KeyType  string `json:"key_type,omitempty"`
	Duration int    `json:"duration,omitempty"`
}

type KeyringTool struct {
	exec executor.Executor
}

func NewKeyring(exec executor.Executor) *KeyringTool {
	return &KeyringTool{exec: exec}
}

func (t *KeyringTool) Name() string { return "kubedagger_keyring" }

func (t *KeyringTool) Description() string {
	return "Access the Linux kernel keyring to list, dump, or monitor cryptographic keys and authentication tokens stored by services. Intercepts keyring syscalls via eBPF to extract keys without triggering audit events."
}

func (t *KeyringTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "dump", "monitor"],
				"description": "Keyring operation: list keys, dump contents, or monitor new additions"
			},
			"key_id": {
				"type": "string",
				"description": "Specific key ID to target"
			},
			"key_type": {
				"type": "string",
				"enum": ["user", "logon", "keyring", "big_key", "all"],
				"description": "Key type filter"
			},
			"duration": {
				"type": "integer",
				"description": "Monitor duration in seconds"
			}
		},
		"required": ["action"]
	}`)
}

func (t *KeyringTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KeyringInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.KeyID, "key_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"keyring", input.Action}
	if input.KeyID != "" {
		args = append(args, "--key-id", input.KeyID)
	}
	if input.KeyType != "" {
		args = append(args, "--key-type", input.KeyType)
	}
	if input.Duration > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", input.Duration))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger keyring failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Keyring: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No keys found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
