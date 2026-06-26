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
	Action         string `json:"action"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	Role           string `json:"role,omitempty"`
	Resource       string `json:"resource,omitempty"`
	Verb           string `json:"verb,omitempty"`
}

type K8sAbuseTool struct {
	exec executor.Executor
}

func NewK8sAbuse(exec executor.Executor) *K8sAbuseTool {
	return &K8sAbuseTool{exec: exec}
}

func (t *K8sAbuseTool) Name() string { return "kubedagger_k8s_abuse" }

func (t *K8sAbuseTool) Description() string {
	return "Exploit Kubernetes RBAC misconfigurations by escalating privileges through service account token theft, role binding manipulation, and impersonation attacks. Uses eBPF to intercept and modify API server authorization decisions."
}

func (t *K8sAbuseTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["escalate", "impersonate", "bind-role", "steal-token", "enum-permissions"],
				"description": "Abuse action to perform"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			},
			"service_account": {
				"type": "string",
				"description": "Target service account name"
			},
			"role": {
				"type": "string",
				"description": "Role or ClusterRole to bind/escalate to"
			},
			"resource": {
				"type": "string",
				"description": "Target resource type for permission check"
			},
			"verb": {
				"type": "string",
				"description": "Action verb to check/grant (get, list, create, delete, etc.)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *K8sAbuseTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input K8sAbuseInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ServiceAccount, "service_account"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Role, "role"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"k8s", "abuse", "--action", input.Action}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.ServiceAccount != "" {
		args = append(args, "--service-account", input.ServiceAccount)
	}
	if input.Role != "" {
		args = append(args, "--role", input.Role)
	}
	if input.Resource != "" {
		args = append(args, "--resource", input.Resource)
	}
	if input.Verb != "" {
		args = append(args, "--verb", input.Verb)
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
	fmt.Fprintf(&sb, "## KubeDagger K8s RBAC Abuse: %s\n\n", input.Action)
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
