package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SigBypassInput struct {
	Action   string `json:"action"`
	Image    string `json:"image,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Registry string `json:"registry,omitempty"`
}

type SigBypassTool struct {
	exec executor.Executor
}

func NewSigBypass(exec executor.Executor) *SigBypassTool {
	return &SigBypassTool{exec: exec}
}

func (t *SigBypassTool) Name() string { return "kubedagger_sig_bypass" }

func (t *SigBypassTool) Description() string {
	return "Bypass Sigstore/cosign image signature verification by hooking the verification process in admission controllers. Allows unsigned or tampered images to pass signature policy checks."
}

func (t *SigBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["bypass", "forge", "disable", "status"],
				"description": "Signature bypass action"
			},
			"image": {
				"type": "string",
				"description": "Image reference to bypass verification for"
			},
			"policy": {
				"type": "string",
				"description": "Policy name to disable"
			},
			"registry": {
				"type": "string",
				"description": "Registry to bypass verification for"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SigBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SigBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Policy, "policy"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Registry, "registry"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sig-bypass", "--action", input.Action}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Policy != "" {
		args = append(args, "--policy", input.Policy)
	}
	if input.Registry != "" {
		args = append(args, "--registry", input.Registry)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger sig-bypass failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Sig Bypass: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Bypass active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
