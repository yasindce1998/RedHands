package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type K8sDiscoverInput struct {
	Namespace  string `json:"namespace,omitempty"`
	Resource   string `json:"resource,omitempty"`
	AllNS      bool   `json:"all_namespaces,omitempty"`
	OutputJSON bool   `json:"output_json,omitempty"`
}

type K8sDiscoverTool struct {
	exec executor.Executor
}

func NewK8sDiscover(exec executor.Executor) *K8sDiscoverTool {
	return &K8sDiscoverTool{exec: exec}
}

func (t *K8sDiscoverTool) Name() string { return "kubedagger_k8s_discover" }

func (t *K8sDiscoverTool) Description() string {
	return "Enumerate Kubernetes cluster resources by intercepting API server responses via eBPF. Discovers pods, services, secrets, configmaps, RBAC roles, and service accounts without making direct API calls that would be logged."
}

func (t *K8sDiscoverTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"namespace": {
				"type": "string",
				"description": "Target namespace to enumerate (default: current)"
			},
			"resource": {
				"type": "string",
				"enum": ["pods", "services", "secrets", "configmaps", "roles", "serviceaccounts", "deployments", "all"],
				"description": "Resource type to discover"
			},
			"all_namespaces": {
				"type": "boolean",
				"description": "Enumerate across all namespaces"
			},
			"output_json": {
				"type": "boolean",
				"description": "Output in JSON format"
			}
		}
	}`)
}

func (t *K8sDiscoverTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input K8sDiscoverInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"k8s", "discover"}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Resource != "" {
		args = append(args, "--resource", input.Resource)
	}
	if input.AllNS {
		args = append(args, "--all-namespaces")
	}
	if input.OutputJSON {
		args = append(args, "--json")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger k8s discover failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger K8s Discovery\n\n")
	if input.Namespace != "" {
		fmt.Fprintf(&sb, "Namespace: %s\n\n", input.Namespace)
	}
	if output == "" {
		sb.WriteString("No resources found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
