package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SidecarInjectInput struct {
	Action    string `json:"action"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Image     string `json:"image,omitempty"`
	Name      string `json:"name,omitempty"`
}

type SidecarInjectTool struct {
	exec executor.Executor
}

func NewSidecarInject(exec executor.Executor) *SidecarInjectTool {
	return &SidecarInjectTool{exec: exec}
}

func (t *SidecarInjectTool) Name() string { return "kubedagger_sidecar_inject" }

func (t *SidecarInjectTool) Description() string {
	return "Inject a sidecar container into a running pod by manipulating the CRI layer via eBPF hooks on containerd/CRI-O. The injected container shares the pod's network and PID namespace without modifying the pod spec in the API server."
}

func (t *SidecarInjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["inject", "remove", "list"],
				"description": "Sidecar action"
			},
			"pod": {
				"type": "string",
				"description": "Target pod name"
			},
			"namespace": {
				"type": "string",
				"description": "Target pod namespace"
			},
			"image": {
				"type": "string",
				"description": "Container image for sidecar"
			},
			"name": {
				"type": "string",
				"description": "Name for injected sidecar container"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SidecarInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SidecarInjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sidecar-inject", "--action", input.Action}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger sidecar-inject failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Sidecar Inject: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
