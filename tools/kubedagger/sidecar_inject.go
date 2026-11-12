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
	Pod       string `json:"pod"`
	Image     string `json:"image,omitempty"`
	Namespace string `json:"namespace,omitempty"`
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
			"pod": {
				"type": "string",
				"description": "Target pod name (required)"
			},
			"image": {
				"type": "string",
				"description": "Container image for the injected sidecar"
			},
			"namespace": {
				"type": "string",
				"description": "Target pod namespace (default: default)"
			}
		},
		"required": ["pod"]
	}`)
}

func (t *SidecarInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SidecarInjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Pod == "" {
		return errorResult("pod is required"), nil
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

	args := []string{"sidecar-inject", "--pod", input.Pod}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
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
		return errorResult(fmt.Sprintf("kubedagger sidecar-inject failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Sidecar Inject\n\n")
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
