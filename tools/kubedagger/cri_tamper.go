package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CRITamperInput struct {
	Runtime      string `json:"runtime,omitempty"`
	Mode         string `json:"mode,omitempty"`
	TargetImage  string `json:"target_image,omitempty"`
	InjectBinary string `json:"inject_binary,omitempty"`
}

type CRITamperTool struct {
	exec executor.Executor
}

func NewCRITamper(exec executor.Executor) *CRITamperTool {
	return &CRITamperTool{exec: exec}
}

func (t *CRITamperTool) Name() string { return "kubedagger_cri_tamper" }

func (t *CRITamperTool) Description() string {
	return "Tamper with the Container Runtime Interface (CRI) by hooking gRPC calls between kubelet and containerd/CRI-O. Modifies container creation to inject image layers, hook entrypoints, or inject environment variables into target images."
}

func (t *CRITamperTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"runtime": {
				"type": "string",
				"enum": ["containerd", "crio"],
				"description": "Container runtime to target (default: containerd)"
			},
			"mode": {
				"type": "string",
				"enum": ["layer-inject", "entrypoint-hook", "env-inject"],
				"description": "Tampering mode (default: layer-inject)"
			},
			"target_image": {
				"type": "string",
				"description": "Target image reference to tamper with"
			},
			"inject_binary": {
				"type": "string",
				"description": "Path to the binary to inject into target containers"
			}
		}
	}`)
}

func (t *CRITamperTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CRITamperInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetImage, "target_image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.InjectBinary, "inject_binary"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cri-tamper"}
	if input.Runtime != "" {
		args = append(args, "--runtime", input.Runtime)
	}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.TargetImage != "" {
		args = append(args, "--target-image", input.TargetImage)
	}
	if input.InjectBinary != "" {
		args = append(args, "--inject-binary", input.InjectBinary)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger cri-tamper failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger CRI Tamper\n\n")
	if output == "" {
		sb.WriteString("Tamper active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
