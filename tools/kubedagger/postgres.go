package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PostgresInput struct {
	Action string `json:"action"`
	Role   string `json:"role,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type PostgresTool struct {
	exec executor.Executor
}

func NewPostgres(exec executor.Executor) *PostgresTool {
	return &PostgresTool{exec: exec}
}

func (t *PostgresTool) Name() string { return "kubedagger_postgres" }

func (t *PostgresTool) Description() string {
	return "Tamper with PostgreSQL authentication via eBPF hooks on the Postgres wire protocol. 'list' shows tracked roles, 'put' stores a secret for a role, and 'delete' removes a role's stored secret."
}

func (t *PostgresTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "put", "delete"],
				"description": "Postgres tampering action"
			},
			"role": {
				"type": "string",
				"description": "Role name (required for put/delete; must not contain '#')"
			},
			"secret": {
				"type": "string",
				"description": "Secret to store for the role (put only)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *PostgresTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PostgresInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Action == "" {
		return errorResult("action is required"), nil
	}
	switch input.Action {
	case "list", "put", "delete":
	default:
		return errorResult("invalid action: must be 'list', 'put', or 'delete'"), nil
	}

	if input.Action != "list" {
		if input.Role == "" {
			return errorResult(fmt.Sprintf("role is required for action=%s", input.Action)), nil
		}
		if strings.Contains(input.Role, "#") {
			return errorResult("role must not contain '#'"), nil
		}
		if err := validateSafeString(input.Role, "role"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateSafeString(input.Secret, "secret"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"postgres", input.Action}
	if input.Role != "" {
		args = append(args, "--role", input.Role)
	}
	if input.Action == "put" && input.Secret != "" {
		args = append(args, "--secret", input.Secret)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger postgres %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Postgres: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
