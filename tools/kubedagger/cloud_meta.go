package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CloudMetaInput struct {
	Provider string `json:"provider,omitempty"`
}

type CloudMetaTool struct {
	exec executor.Executor
}

func NewCloudMeta(exec executor.Executor) *CloudMetaTool {
	return &CloudMetaTool{exec: exec}
}

func (t *CloudMetaTool) Name() string { return "kubedagger_cloud_meta" }

func (t *CloudMetaTool) Description() string {
	return "Query the cloud provider metadata service (AWS IMDS, GCP metadata, Azure IMDS) for the current node. Retrieves IAM credentials and instance identity documents as JSON; use provider 'auto' to detect the cloud."
}

func (t *CloudMetaTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"provider": {
				"type": "string",
				"enum": ["aws", "gcp", "azure", "auto"],
				"description": "Cloud provider (default: auto-detect)"
			}
		}
	}`)
}

func (t *CloudMetaTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CloudMetaInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"cloud", "meta"}
	if input.Provider != "" {
		args = append(args, "--provider", input.Provider)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger cloud meta failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Cloud Metadata\n\n")
	if input.Provider != "" {
		fmt.Fprintf(&sb, "Provider: %s\n\n", input.Provider)
	}
	if output == "" {
		sb.WriteString("No metadata retrieved.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
