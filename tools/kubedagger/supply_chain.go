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
	Action   string `json:"action"`
	Image    string `json:"image,omitempty"`
	Registry string `json:"registry,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

type SupplyChainTool struct {
	exec executor.Executor
}

func NewSupplyChain(exec executor.Executor) *SupplyChainTool {
	return &SupplyChainTool{exec: exec}
}

func (t *SupplyChainTool) Name() string { return "kubedagger_supply_chain" }

func (t *SupplyChainTool) Description() string {
	return "Manipulate OCI container images in transit or at the registry level. Intercepts image pulls via eBPF to inject layers, modify entrypoints, or replace images entirely. Can also poison local image cache."
}

func (t *SupplyChainTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["intercept", "poison-cache", "inject-layer", "replace", "status"],
				"description": "Supply chain attack action"
			},
			"image": {
				"type": "string",
				"description": "Target image reference (e.g., nginx:latest)"
			},
			"registry": {
				"type": "string",
				"description": "Target registry to intercept"
			},
			"payload": {
				"type": "string",
				"description": "Payload to inject (path or command)"
			},
			"tag": {
				"type": "string",
				"description": "Tag to target for replacement"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SupplyChainTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SupplyChainInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Registry, "registry"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Tag, "tag"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"supply-chain", "--action", input.Action}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Registry != "" {
		args = append(args, "--registry", input.Registry)
	}
	if input.Payload != "" {
		args = append(args, "--payload", input.Payload)
	}
	if input.Tag != "" {
		args = append(args, "--tag", input.Tag)
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
	fmt.Fprintf(&sb, "## KubeDagger Supply Chain: %s\n\n", input.Action)
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
