package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// InjectTool wraps `barzakh-adversary inject-single` (verified against
// adversary_main.rs):
//
//	inject-single --input <fw image> --output <implanted image> --payload <name>
//	              [--arch x86-64|aarch64|riscv64|power64|armv7] [--size <bytes>]
//
// --payload takes a payload NAME from the adversary catalog (the same
// namespace as `generate`, see barzakh_list), not a file path. --size is in
// bytes and defaults to the input file size (min 0x10000). The command
// overlays freshly generated payload bytes at offset 0 of the input image.
// inject-single has no detection-exit semantics: the adversary main() exits 1
// only on failure, so a plain exec.Run is used.
type InjectInput struct {
	Input   string `json:"input"`
	Output  string `json:"output"`
	Payload string `json:"payload"`
	Arch    string `json:"arch,omitempty"`
	Size    string `json:"size,omitempty"`
}

type InjectTool struct {
	exec executor.Executor
}

func NewInject(exec executor.Executor) *InjectTool {
	return &InjectTool{exec: exec}
}

func (t *InjectTool) Name() string { return "barzakh_inject" }

func (t *InjectTool) Description() string {
	return "Implant a bootkit payload into an existing UEFI firmware image for adversary simulation: generates the named payload (see barzakh_list) and overlays it at offset 0 of the input image, writing the implanted copy to the output path so detection coverage can be tested with barzakh_scan. HIGH IMPACT: this creates real malicious firmware for adversary simulation in authorized lab environments only; approval-gated."
}

func (t *InjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"input": {
				"type": "string",
				"description": "Path to the existing firmware image to implant the payload into (must exist)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the implanted firmware image"
			},
			"payload": {
				"type": "string",
				"description": "Adversary payload name to inject (e.g. trampoline, secureboot_bypass; see barzakh_list)"
			},
			"arch": {
				"type": "string",
				"enum": ["x86-64", "aarch64", "riscv64", "power64", "armv7"],
				"description": "Target architecture (default: x86-64)"
			},
			"size": {
				"type": "string",
				"description": "Payload generation size in bytes (defaults to the input file size)"
			}
		},
		"required": ["input", "output", "payload"]
	}`)
}

func (t *InjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input InjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Input == "" {
		return errorResult("input firmware path is required"), nil
	}
	if err := validatePath(input.Input, "input"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingFile(input.Input, "input"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Output == "" {
		return errorResult("output path is required"), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePayloadName(input.Payload); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateBarzakhArch(input.Arch); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.Size, "size"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"inject-single", "--input", input.Input, "--output", input.Output, "--payload", input.Payload}
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
		return errorResult(fmt.Sprintf("barzakh-adversary inject-single failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Firmware Injection Result\n\n")
	fmt.Fprintf(&sb, "- **Input:** %s\n", input.Input)
	fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
	fmt.Fprintf(&sb, "- **Payload:** %s\n", input.Payload)
	if input.Arch != "" {
		fmt.Fprintf(&sb, "- **Arch:** %s\n", input.Arch)
	}
	if input.Size != "" {
		fmt.Fprintf(&sb, "- **Size:** %s bytes\n", input.Size)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Injection completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
