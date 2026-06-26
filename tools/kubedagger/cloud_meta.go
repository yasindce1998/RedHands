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
	Endpoint string `json:"endpoint,omitempty"`
	Token    bool   `json:"token,omitempty"`
	UserData bool   `json:"user_data,omitempty"`
	All      bool   `json:"all,omitempty"`
}

type CloudMetaTool struct {
	exec executor.Executor
}

func NewCloudMeta(exec executor.Executor) *CloudMetaTool {
	return &CloudMetaTool{exec: exec}
}

func (t *CloudMetaTool) Name() string { return "kubedagger_cloud_meta" }

func (t *CloudMetaTool) Description() string {
	return "Access cloud provider metadata services (AWS IMDS, GCP metadata, Azure IMDS) by bypassing network policies with eBPF. Retrieves IAM credentials, instance identity tokens, user-data scripts, and cloud provider configuration."
}

func (t *CloudMetaTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"provider": {
				"type": "string",
				"enum": ["aws", "gcp", "azure", "auto"],
				"description": "Cloud provider (auto-detect if not specified)"
			},
			"endpoint": {
				"type": "string",
				"description": "Custom metadata endpoint URL"
			},
			"token": {
				"type": "boolean",
				"description": "Retrieve IAM/instance identity token"
			},
			"user_data": {
				"type": "boolean",
				"description": "Retrieve instance user-data/startup scripts"
			},
			"all": {
				"type": "boolean",
				"description": "Dump all available metadata"
			}
		}
	}`)
}

func (t *CloudMetaTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CloudMetaInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Endpoint, "endpoint"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cloud", "meta"}
	if input.Provider != "" {
		args = append(args, "--provider", input.Provider)
	}
	if input.Endpoint != "" {
		args = append(args, "--endpoint", input.Endpoint)
	}
	if input.Token {
		args = append(args, "--token")
	}
	if input.UserData {
		args = append(args, "--user-data")
	}
	if input.All {
		args = append(args, "--all")
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
