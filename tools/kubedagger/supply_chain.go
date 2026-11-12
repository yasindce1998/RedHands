package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SupplyChainInput struct {
	Mode        string `json:"mode,omitempty"`
	TargetImage string `json:"target_image,omitempty"`
	Payload     string `json:"payload,omitempty"`
}

type SupplyChainTool struct {
	exec executor.Executor
}

func NewSupplyChain(exec executor.Executor) *SupplyChainTool {
	return &SupplyChainTool{exec: exec}
}

func (t *SupplyChainTool) Name() string { return "kubedagger_supply_chain" }

func (t *SupplyChainTool) Description() string {
	return "Attack the image supply chain. Injects an attacker-controlled layer into a target OCI image, or replaces the image reference in Kubernetes manifests so workloads pull the attacker's image."
}

func (t *SupplyChainTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["layer-inject", "manifest-replace"],
				"description": "Attack mode (default: layer-inject)"
			},
			"target_image": {
				"type": "string",
				"description": "Target image reference (e.g., nginx:latest)"
			},
			"payload": {
				"type": "string",
				"description": "Payload to inject (layer path or replacement image reference)"
			}
		}
	}`)
}

func (t *SupplyChainTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SupplyChainInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetImage, "target_image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"supply-chain"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.TargetImage != "" {
		args = append(args, "--target-image", input.TargetImage)
	}
	if input.Payload != "" {
		args = append(args, "--payload", input.Payload)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger supply-chain failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Supply Chain\n\n")
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
