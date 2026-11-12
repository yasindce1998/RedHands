package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// EspBuildTool wraps `barzakh-adversary esp build` (verified against
// adversary_main.rs):
//
//	esp build --payload <payload binary> --output <esp image>
//	          [--size <MB>] [--bootable]
//
// --size is in MEGABYTES (u32, default 64), unlike generate's byte-sized
// --size. --bootable defaults to false in the CLI (synthetic scan image);
// when set, a real FAT16 filesystem bootable by OVMF is built with the
// payload embedded as \EFI\BOOT\BOOTX64.EFI. esp build has no detection-exit
// semantics (adversary main() exits 1 only on failure).
type EspBuildInput struct {
	Payload  string `json:"payload"`
	Output   string `json:"output"`
	Size     string `json:"size,omitempty"`
	Bootable bool   `json:"bootable,omitempty"`
}

type EspBuildTool struct {
	exec executor.Executor
}

func NewEspBuild(exec executor.Executor) *EspBuildTool {
	return &EspBuildTool{exec: exec}
}

func (t *EspBuildTool) Name() string { return "barzakh_esp_build" }

func (t *EspBuildTool) Description() string {
	return "Build an EFI System Partition (ESP) disk image containing a bootkit payload, for QEMU/OVMF lab boot testing of detection coverage. With bootable=true the image is a real FAT16 filesystem (payload embedded as \\EFI\\BOOT\\BOOTX64.EFI) that OVMF can boot; the default (bootable=false) builds the synthetic scan image barzakh-scanner expects. HIGH IMPACT: this packages real adversary payload artifacts for authorized lab environments only; approval-gated."
}

func (t *EspBuildTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"payload": {
				"type": "string",
				"description": "Path to the payload binary to embed, e.g. produced by barzakh_generate (must exist)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the ESP image (barzakh-adversary default: esp.img)"
			},
			"size": {
				"type": "string",
				"description": "ESP image size in megabytes (default: 64)"
			},
			"bootable": {
				"type": "boolean",
				"description": "Build a real FAT16 filesystem bootable by OVMF with the payload as \\EFI\\BOOT\\BOOTX64.EFI (default: false, synthetic scan image)"
			}
		},
		"required": ["payload", "output"]
	}`)
}

func (t *EspBuildTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input EspBuildInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Payload == "" {
		return errorResult("payload path is required"), nil
	}
	if err := validatePath(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingFile(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Output == "" {
		return errorResult("output path is required"), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.Size, "size"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"esp", "build", "--payload", input.Payload, "--output", input.Output}
	if input.Size != "" {
		args = append(args, "--size", input.Size)
	}
	if input.Bootable {
		args = append(args, "--bootable")
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary esp build failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## ESP Image Build Result\n\n")
	fmt.Fprintf(&sb, "- **Payload:** %s\n", input.Payload)
	fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
	if input.Size != "" {
		fmt.Fprintf(&sb, "- **Size:** %s MB\n", input.Size)
	}
	if input.Bootable {
		sb.WriteString("- **Bootable:** real FAT16 ESP (\\EFI\\BOOT\\BOOTX64.EFI)\n")
	} else {
		sb.WriteString("- **Bootable:** no (synthetic scan image)\n")
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("ESP build completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
