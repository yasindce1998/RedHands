package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type K8sAbuseInput struct {
	Action    string `json:"action,omitempty"`
	Token     string `json:"token,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type K8sAbuseTool struct {
	exec executor.Executor
}

func NewK8sAbuse(exec executor.Executor) *K8sAbuseTool {
	return &K8sAbuseTool{exec: exec}
}

func (t *K8sAbuseTool) Name() string { return "kubedagger_k8s_abuse" }

func (t *K8sAbuseTool) Description() string {
	return "Abuse Kubernetes RBAC using a service account token. Enumerates the permissions the token grants, attempts privilege escalation, or dumps secrets accessible to the token."
}

func (t *K8sAbuseTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["enum", "escalate", "dump-secrets"],
				"description": "Abuse action: enumerate permissions, escalate privileges, or dump secrets (default: enum)"
			},
			"token": {
				"type": "string",
				"description": "Service account token to use (defaults to the pod's mounted token)"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace (default: default)"
			}
		}
	}`)
}

func (t *K8sAbuseTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input K8sAbuseInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Token, "token"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"k8s", "abuse"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Token != "" {
		args = append(args, "--token", input.Token)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger k8s abuse failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	action := input.Action
	if action == "" {
		action = "enum"
	}
	fmt.Fprintf(&sb, "## KubeDagger K8s RBAC Abuse: %s\n\n", action)
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
