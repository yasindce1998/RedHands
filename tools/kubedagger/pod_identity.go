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
	TargetPod string `json:"target_pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Action    string `json:"action,omitempty"`
}

type PodIdentityTool struct {
	exec executor.Executor
}

func NewPodIdentity(exec executor.Executor) *PodIdentityTool {
	return &PodIdentityTool{exec: exec}
}

func (t *PodIdentityTool) Name() string { return "kubedagger_pod_identity" }

func (t *PodIdentityTool) Description() string {
	return "Steal or impersonate pod cloud identities (AWS IRSA, GCP Workload Identity, Azure Managed Identity). Intercepts the target pod's token exchanges or metadata requests to assume the cloud IAM role bound to it."
}

func (t *PodIdentityTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target_pod": {
				"type": "string",
				"description": "Pod whose cloud identity is targeted"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace of the target pod (default: default)"
			},
			"action": {
				"type": "string",
				"enum": ["steal", "impersonate"],
				"description": "Identity operation (default: steal)"
			}
		}
	}`)
}

func (t *PodIdentityTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PodIdentityInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetPod, "target_pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"pod-identity"}
	if input.TargetPod != "" {
		args = append(args, "--target-pod", input.TargetPod)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
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
	sb.WriteString("## KubeDagger Pod Identity\n\n")
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
