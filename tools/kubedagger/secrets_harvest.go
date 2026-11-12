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
	Sources string `json:"sources,omitempty"`
}

type SecretsHarvestTool struct {
	exec executor.Executor
}

func NewSecretsHarvest(exec executor.Executor) *SecretsHarvestTool {
	return &SecretsHarvestTool{exec: exec}
}

func (t *SecretsHarvestTool) Name() string { return "kubedagger_secrets_harvest" }

func (t *SecretsHarvestTool) Description() string {
	return "Harvest secrets and credentials from multiple sources: environment variables, Kubernetes secrets, cloud metadata, docker configs, vault tokens, and kubeconfig files. Aggregates all discovered credentials in one pass."
}

func (t *SecretsHarvestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"sources": {
				"type": "string",
				"enum": ["env", "k8s", "cloud", "docker", "vault", "kubeconfig", "all"],
				"description": "Comma-separable source categories to harvest from (default: all)"
			}
		}
	}`)
}

func (t *SecretsHarvestTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SecretsHarvestInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Sources, "sources"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"secrets", "harvest"}
	if input.Sources != "" {
		args = append(args, "--sources", input.Sources)
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
