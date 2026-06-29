package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type GenerateInput struct {
	Payload string `json:"payload"`
	Output  string `json:"output"`
	Arch    string `json:"arch,omitempty"`
	Size    string `json:"size,omitempty"`
}

type GenerateTool struct {
	exec executor.Executor
}

func NewGenerate(exec executor.Executor) *GenerateTool {
	return &GenerateTool{exec: exec}
}

func (t *GenerateTool) Name() string { return "barzakh_generate" }

func (t *GenerateTool) Description() string {
	return "Generate a UEFI bootkit payload for red-team testing. Supports 33 payload types including trampoline, boot_services_hook, pe_inject, secureboot_bypass, blacklotus_mok, acpi_backdoor, logofail_image, pixiefail_dhcp, arm_trustzone, riscv_opensbi and more. Use 'barzakh_list' to see all available payloads."
}

func (t *GenerateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"payload": {
				"type": "string",
				"description": "Payload name (e.g. trampoline, boot_services_hook, pe_inject, secureboot_bypass)"
			},
			"output": {
				"type": "string",
				"description": "Output file path for the generated bootkit binary"
			},
			"arch": {
				"type": "string",
				"enum": ["x86-64", "aarch64", "riscv64"],
				"description": "Target architecture (default: x86-64)"
			},
			"size": {
				"type": "string",
				"description": "Image size in bytes (default: 65536)"
			}
		},
		"required": ["payload", "output"]
	}`)
}

func (t *GenerateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input GenerateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePayloadName(input.Payload); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Output == "" {
		return errorResult("output path is required"), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Size, "size"); err != nil {
		return errorResult(err.Error()), nil
	}

	validArchs := map[string]bool{"x86-64": true, "aarch64": true, "riscv64": true}
	if input.Arch != "" && !validArchs[input.Arch] {
		return errorResult("invalid arch: must be x86-64, aarch64, or riscv64"), nil
	}

	args := []string{"generate", "--payload", input.Payload, "--output", input.Output}
	if input.Arch != "" {
		args = append(args, "--arch", input.Arch)
	}
	if input.Size != "" {
		args = append(args, "--size", input.Size)
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary generate failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Generated UEFI Bootkit Payload\n\n")
	fmt.Fprintf(&sb, "- **Payload:** %s\n", input.Payload)
	fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
	if input.Arch != "" {
		fmt.Fprintf(&sb, "- **Arch:** %s\n", input.Arch)
	}
	if input.Size != "" {
		fmt.Fprintf(&sb, "- **Size:** %s bytes\n", input.Size)
	}
	if output != "" {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
