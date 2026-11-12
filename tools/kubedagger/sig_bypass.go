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
	Mode        string `json:"mode,omitempty"`
	TargetImage string `json:"target_image,omitempty"`
}

type SigBypassTool struct {
	exec executor.Executor
}

func NewSigBypass(exec executor.Executor) *SigBypassTool {
	return &SigBypassTool{exec: exec}
}

func (t *SigBypassTool) Name() string { return "kubedagger_sig_bypass" }

func (t *SigBypassTool) Description() string {
	return "Bypass Sigstore/cosign image signature verification. Injects a forged signature for the target image or disables signature verification entirely in admission policy, allowing unsigned or tampered images to deploy."
}

func (t *SigBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["inject-sig", "disable-verify"],
				"description": "Bypass mode (default: inject-sig)"
			},
			"target_image": {
				"type": "string",
				"description": "Image reference to bypass verification for"
			}
		}
	}`)
}

func (t *SigBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SigBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetImage, "target_image"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sig-bypass"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.TargetImage != "" {
		args = append(args, "--target-image", input.TargetImage)
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
	sb.WriteString("## KubeDagger Sig Bypass\n\n")
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
