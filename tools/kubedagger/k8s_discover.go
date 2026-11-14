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
	Namespace string `json:"namespace,omitempty"`
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
				"description": "Target namespace to enumerate (default: default). Passed explicitly because the CLI default is unreliable"
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

	namespace := input.Namespace
	if namespace == "" {
		namespace = "default"
	}

	args := []string{"k8s", "discover", "--namespace", namespace}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger k8s discover failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	// The pinned kubedagger-client v0.5.0 binary exits 0 with empty stdout
	// when discovery fails (no kubeconfig, daemon down); the failure text
	// goes to stderr only (real capture in
	// testdata/kubedagger/k8s-discover-no-kubeconfig.stderr). An empty
	// stdout combined with a non-empty stderr is therefore a failure, not a
	// genuinely empty cluster. When stderr is also empty the result really
	// is empty and stays a success below.
	stderrText := strings.TrimSpace(string(result.Stderr))
	if output == "" && stderrText != "" {
		return errorResult(fmt.Sprintf(
			"k8s discovery produced no output — the client reported:\n%s",
			stderrText,
		)), nil
	}
	var sb strings.Builder
	sb.WriteString("## KubeDagger K8s Discovery\n\n")
	fmt.Fprintf(&sb, "Namespace: %s\n\n", namespace)
	switch {
	case output == "":
		sb.WriteString("No resources found.\n")
	case json.Valid([]byte(output)):
		// `k8s discover` prints a pretty-printed ClusterReport JSON object
		// (cmd/kubedagger-client/run/k8s/discovery.go marshals the report
		// with MarshalIndent). Fence it as JSON so campaign dataflow can
		// reference ${step.json.nodes.0.ip} and record rules can select
		// the nodes/pods arrays; see testdata/kubedagger/.
		sb.WriteString("```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	default:
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
