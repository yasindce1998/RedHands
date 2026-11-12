package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var qemuActions = []string{"run", "dump"}

// QemuTool wraps `barzakh-adversary qemu run` and `qemu dump` (verified
// against adversary_main.rs):
//
//	qemu run --esp <esp image> [--arch ...] [--firmware <OVMF path>]
//	         [--memory <MB>] [--timeout <secs>]
//	qemu dump --output <dump path> [--arch ...]
//
// `qemu run` is one-shot: it prints the QEMU launch configuration (binary,
// memory, firmware, full command line) for the ESP image without booting the
// VM. `qemu dump` captures a memory dump via QEMU; it is a stub in the
// current CLI and bails without a running QEMU instance. Neither has
// detection-exit semantics (adversary main() exits 1 only on failure).
type QemuInput struct {
	Action   string `json:"action"`
	Esp      string `json:"esp,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Memory   string `json:"memory,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Output   string `json:"output,omitempty"`
}

type QemuTool struct {
	exec executor.Executor
}

func NewQemu(exec executor.Executor) *QemuTool {
	return &QemuTool{exec: exec}
}

func (t *QemuTool) Name() string { return "barzakh_qemu" }

func (t *QemuTool) Description() string {
	return "QEMU/OVMF emulation integration for detection validation: run prints the QEMU launch configuration (binary, memory, OVMF firmware, command line) for an ESP disk image without booting it, and dump captures a memory dump from a QEMU instance to a file. Use the printed command with an ESP image built by barzakh_esp_build to execute implanted firmware in an emulated OVMF environment. If dump ever blocks on a live VM, the executor timeout (REDHANDS_TIMEOUT, default 300s) applies. HIGH IMPACT: this is part of the adversary boot-validation path for authorized lab environments only; approval-gated."
}

func (t *QemuTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["run", "dump"],
				"description": "run: show the QEMU launch configuration for an ESP image; dump: capture a memory dump"
			},
			"esp": {
				"type": "string",
				"description": "ESP disk image to boot (required for run; e.g. built by barzakh_esp_build, must exist)"
			},
			"firmware": {
				"type": "string",
				"description": "OVMF/firmware path passed to QEMU (run only)"
			},
			"arch": {
				"type": "string",
				"enum": ["x86-64", "aarch64", "riscv64", "power64", "armv7"],
				"description": "Target architecture, selects the qemu-system binary (default: x86-64)"
			},
			"memory": {
				"type": "string",
				"description": "VM memory in MB (run only; default: 256)"
			},
			"timeout": {
				"type": "string",
				"description": "QEMU timeout in seconds (run only; default: 30)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the memory dump (required for dump)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *QemuTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input QemuInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if !isValidAction(qemuActions, input.Action) {
		return errorResult("invalid action: must be one of " + strings.Join(qemuActions, ", ")), nil
	}
	if err := validateBarzakhArch(input.Arch); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "run":
		if input.Esp == "" {
			return errorResult("esp path is required for run"), nil
		}
		if err := validatePath(input.Esp, "esp"); err != nil {
			return errorResult(err.Error()), nil
		}
		if err := validateExistingFile(input.Esp, "esp"); err != nil {
			return errorResult(err.Error()), nil
		}
		if err := validatePath(input.Firmware, "firmware"); err != nil {
			return errorResult(err.Error()), nil
		}
		if err := validatePositiveInt(input.Memory, "memory"); err != nil {
			return errorResult(err.Error()), nil
		}
		if err := validatePositiveInt(input.Timeout, "timeout"); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"qemu", "run", "--esp", input.Esp}
		if input.Arch != "" {
			args = append(args, "--arch", input.Arch)
		}
		if input.Firmware != "" {
			args = append(args, "--firmware", input.Firmware)
		}
		if input.Memory != "" {
			args = append(args, "--memory", input.Memory)
		}
		if input.Timeout != "" {
			args = append(args, "--timeout", input.Timeout)
		}
	case "dump":
		if input.Output == "" {
			return errorResult("output path is required for dump"), nil
		}
		if err := validatePath(input.Output, "output"); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"qemu", "dump", "--output", input.Output}
		if input.Arch != "" {
			args = append(args, "--arch", input.Arch)
		}
	}

	result, err := t.exec.Run(ctx, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary qemu %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## QEMU %s\n\n", strings.ToUpper(input.Action[:1])+input.Action[1:])
	if input.Action == "run" {
		fmt.Fprintf(&sb, "- **ESP:** %s\n", input.Esp)
		if input.Firmware != "" {
			fmt.Fprintf(&sb, "- **Firmware:** %s\n", input.Firmware)
		}
		if input.Arch != "" {
			fmt.Fprintf(&sb, "- **Arch:** %s\n", input.Arch)
		}
		if input.Memory != "" {
			fmt.Fprintf(&sb, "- **Memory:** %s MB\n", input.Memory)
		}
		if input.Timeout != "" {
			fmt.Fprintf(&sb, "- **Timeout:** %s s\n", input.Timeout)
		}
	} else {
		fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
		if input.Arch != "" {
			fmt.Fprintf(&sb, "- **Arch:** %s\n", input.Arch)
		}
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("QEMU command completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
