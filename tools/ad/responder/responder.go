package responder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// StartTool starts Responder on an interface.
type StartTool struct {
	exec executor.Executor
}

type startInput struct {
	Interface   string `json:"interface"`
	AnalyzeMode bool   `json:"analyze_mode,omitempty"`
	Verbose     bool   `json:"verbose,omitempty"`
	WPAD        bool   `json:"wpad,omitempty"`
	Fingerprint bool   `json:"fingerprint,omitempty"`
}

func NewStartTool(exec executor.Executor) *StartTool {
	return &StartTool{exec: exec}
}

func (t *StartTool) Name() string { return "responder_start" }

func (t *StartTool) Description() string {
	return "Start Responder on a network interface to capture LLMNR/NBT-NS/MDNS poisoned credentials. Supports analyze-only mode, WPAD rogue proxy, and OS fingerprinting."
}

func (t *StartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Network interface to listen on (e.g. eth0)"
			},
			"analyze_mode": {
				"type": "boolean",
				"description": "Run in analyze mode without poisoning (-A flag)"
			},
			"verbose": {
				"type": "boolean",
				"description": "Enable verbose output (-v flag)"
			},
			"wpad": {
				"type": "boolean",
				"description": "Enable WPAD rogue proxy (-w flag)"
			},
			"fingerprint": {
				"type": "boolean",
				"description": "Enable OS fingerprinting (-f flag)"
			}
		},
		"required": ["interface"]
	}`)
}

func (t *StartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input startInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	args := []string{"-I", input.Interface}
	if input.AnalyzeMode {
		args = append(args, "-A")
	}
	if input.Verbose {
		args = append(args, "-v")
	}
	if input.WPAD {
		args = append(args, "-w")
	}
	if input.Fingerprint {
		args = append(args, "-f")
	}

	result, err := t.exec.Run(ctx, "responder", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("responder start failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Responder Started\n\n")
	fmt.Fprintf(&sb, "Interface: %s\n", input.Interface)
	if input.AnalyzeMode {
		sb.WriteString("Mode: Analyze (passive)\n")
	}
	if output != "" {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// AnalyzeTool runs Responder in analyze-only mode.
type AnalyzeTool struct {
	exec executor.Executor
}

type analyzeInput struct {
	Interface string `json:"interface"`
}

func NewAnalyzeTool(exec executor.Executor) *AnalyzeTool {
	return &AnalyzeTool{exec: exec}
}

func (t *AnalyzeTool) Name() string { return "responder_analyze" }

func (t *AnalyzeTool) Description() string {
	return "Run Responder in analyze-only mode to passively observe LLMNR/NBT-NS/MDNS traffic without poisoning responses. Useful for reconnaissance before active attacks."
}

func (t *AnalyzeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Network interface to listen on (e.g. eth0)"
			}
		},
		"required": ["interface"]
	}`)
}

func (t *AnalyzeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input analyzeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	args := []string{"-I", input.Interface, "-A"}

	result, err := t.exec.Run(ctx, "responder", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("responder analyze failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Responder Analyze Mode\n\n")
	fmt.Fprintf(&sb, "Interface: %s\n", input.Interface)
	sb.WriteString("Mode: Analyze (passive, no poisoning)\n")
	if output != "" {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// LogsTool reads Responder log files.
type LogsTool struct {
	exec executor.Executor
}

type logsInput struct {
	LogDir string `json:"log_dir,omitempty"`
	Filter string `json:"filter,omitempty"`
}

func NewLogsTool(exec executor.Executor) *LogsTool {
	return &LogsTool{exec: exec}
}

func (t *LogsTool) Name() string { return "responder_logs" }

func (t *LogsTool) Description() string {
	return "Read and search Responder log files for captured credentials, hashes, and poisoning events."
}

func (t *LogsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"log_dir": {
				"type": "string",
				"description": "Path to Responder logs directory (default: /usr/share/responder/logs)"
			},
			"filter": {
				"type": "string",
				"description": "Filter string to grep for in log files (e.g. NTLMv2, WPAD, specific IP)"
			}
		}
	}`)
}

func (t *LogsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input logsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	logDir := input.LogDir
	if logDir == "" {
		logDir = "/usr/share/responder/logs"
	}

	if err := validateInput(logDir); err != nil {
		return errorResult("invalid log_dir: " + err.Error()), nil
	}

	if input.Filter != "" {
		if err := validateInput(input.Filter); err != nil {
			return errorResult("invalid filter: " + err.Error()), nil
		}
	}

	var result *executor.Result
	var err error

	if input.Filter != "" {
		result, err = t.exec.Run(ctx, "find", logDir, "-name", "*.txt", "-exec", "grep", "-l", input.Filter, "{}", ";")
	} else {
		result, err = t.exec.Run(ctx, "find", logDir, "-name", "*.txt", "-exec", "cat", "{}", ";")
	}

	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("failed to read responder logs: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Responder Logs\n\n")
	fmt.Fprintf(&sb, "Directory: %s\n", logDir)
	if input.Filter != "" {
		fmt.Fprintf(&sb, "Filter: %s\n", input.Filter)
	}
	if output == "" {
		sb.WriteString("\nNo log entries found.\n")
	} else {
		sb.WriteString("\n```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// StatusTool checks if Responder is currently running.
type StatusTool struct {
	exec executor.Executor
}

func NewStatusTool(exec executor.Executor) *StatusTool {
	return &StatusTool{exec: exec}
}

func (t *StatusTool) Name() string { return "responder_status" }

func (t *StatusTool) Description() string {
	return "Check if Responder is currently running and display active process information."
}

func (t *StatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`)
}

func (t *StatusTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	result, err := t.exec.Run(ctx, "pgrep", "-a", "responder")
	if err != nil {
		// pgrep exits non-zero when no process is found
		return textResult("## Responder Status\n\nResponder is **not running**."), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Responder Status\n\n")
	sb.WriteString("Responder is **running**.\n\n")
	if output != "" {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
