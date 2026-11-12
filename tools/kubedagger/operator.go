package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// operatorGlobalArgs builds the global flag prefix that the kubedagger-operator
// binary (Go stdlib flag package) requires BEFORE the subcommand. The key is
// required and falls back to the KUBEDAGGER_OPERATOR_KEY environment variable.
func operatorGlobalArgs(key, addr string) ([]string, error) {
	if key == "" {
		key = os.Getenv("KUBEDAGGER_OPERATOR_KEY")
	}
	if key == "" {
		return nil, fmt.Errorf("operator key is required: pass the key parameter or set KUBEDAGGER_OPERATOR_KEY")
	}
	if err := validateSafeString(key, "key"); err != nil {
		return nil, err
	}
	if addr == "" {
		addr = "127.0.0.1:9443"
	}
	if err := validateSafeString(addr, "addr"); err != nil {
		return nil, err
	}
	return []string{"-key", key, "-addr", addr}, nil
}

// Operator Agents

type OperatorAgentsInput struct {
	Key  string `json:"key,omitempty"`
	Addr string `json:"addr,omitempty"`
}

type OperatorAgentsTool struct {
	exec executor.Executor
}

func NewOperatorAgents(exec executor.Executor) *OperatorAgentsTool {
	return &OperatorAgentsTool{exec: exec}
}

func (t *OperatorAgentsTool) Name() string { return "kubedagger_operator_agents" }

func (t *OperatorAgentsTool) Description() string {
	return "List KubeDagger agents registered with the operator. Returns a table of deployed eBPF agents across the cluster."
}

func (t *OperatorAgentsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"key": {
				"type": "string",
				"description": "Operator API key (required; falls back to KUBEDAGGER_OPERATOR_KEY env var)"
			},
			"addr": {
				"type": "string",
				"description": "Operator address (default: 127.0.0.1:9443)"
			}
		},
		"required": ["key"]
	}`)
}

func (t *OperatorAgentsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorAgentsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	globalArgs, err := operatorGlobalArgs(input.Key, input.Addr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	args := append(globalArgs, "agents")

	result, err := t.exec.Run(ctx, "kubedagger-operator", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger operator agents failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Operator Agents\n\n")
	if output == "" {
		sb.WriteString("No agents found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Operator Shell

type OperatorShellInput struct {
	Key     string `json:"key,omitempty"`
	Addr    string `json:"addr,omitempty"`
	AgentID string `json:"agent_id"`
	Command string `json:"command"`
}

type OperatorShellTool struct {
	exec executor.Executor
}

func NewOperatorShell(exec executor.Executor) *OperatorShellTool {
	return &OperatorShellTool{exec: exec}
}

func (t *OperatorShellTool) Name() string { return "kubedagger_operator_shell" }

func (t *OperatorShellTool) Description() string {
	return "Queue a shell command on a remote KubeDagger agent via the operator C2 channel. The command is dispatched as an asynchronous task and results can be retrieved with the task status tools."
}

func (t *OperatorShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"key": {
				"type": "string",
				"description": "Operator API key (required; falls back to KUBEDAGGER_OPERATOR_KEY env var)"
			},
			"addr": {
				"type": "string",
				"description": "Operator address (default: 127.0.0.1:9443)"
			},
			"agent_id": {
				"type": "string",
				"description": "Target agent ID"
			},
			"command": {
				"type": "string",
				"description": "Shell command to execute (no shell metacharacters allowed)"
			}
		},
		"required": ["key", "agent_id", "command"]
	}`)
}

func (t *OperatorShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.AgentID == "" {
		return errorResult("agent_id is required"), nil
	}
	if input.Command == "" {
		return errorResult("command is required"), nil
	}
	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Command, "command"); err != nil {
		return errorResult(err.Error()), nil
	}

	globalArgs, err := operatorGlobalArgs(input.Key, input.Addr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	args := append(globalArgs, "shell", input.AgentID, input.Command)

	result, err := t.exec.Run(ctx, "kubedagger-operator", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger operator shell failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Operator Shell\n\n")
	if output == "" {
		sb.WriteString("Command queued (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Operator Module

type OperatorModuleInput struct {
	Key     string `json:"key,omitempty"`
	Addr    string `json:"addr,omitempty"`
	AgentID string `json:"agent_id"`
	Module  string `json:"module"`
	Config  string `json:"config,omitempty"`
}

type OperatorModuleTool struct {
	exec executor.Executor
}

func NewOperatorModule(exec executor.Executor) *OperatorModuleTool {
	return &OperatorModuleTool{exec: exec}
}

func (t *OperatorModuleTool) Name() string { return "kubedagger_operator_module" }

func (t *OperatorModuleTool) Description() string {
	return "Dispatch an eBPF module load request to a remote KubeDagger agent via the operator. Modules provide specific capabilities (network interception, syscall hooking, etc.) and are configured with key=value pairs."
}

func (t *OperatorModuleTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"key": {
				"type": "string",
				"description": "Operator API key (required; falls back to KUBEDAGGER_OPERATOR_KEY env var)"
			},
			"addr": {
				"type": "string",
				"description": "Operator address (default: 127.0.0.1:9443)"
			},
			"agent_id": {
				"type": "string",
				"description": "Target agent ID"
			},
			"module": {
				"type": "string",
				"description": "Module name to load"
			},
			"config": {
				"type": "string",
				"description": "Module configuration as space-separated key=value pairs (e.g. 'mode=stealth rate=50')"
			}
		},
		"required": ["key", "agent_id", "module"]
	}`)
}

func (t *OperatorModuleTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorModuleInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.AgentID == "" {
		return errorResult("agent_id is required"), nil
	}
	if input.Module == "" {
		return errorResult("module is required"), nil
	}
	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Module, "module"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Config, "config"); err != nil {
		return errorResult(err.Error()), nil
	}

	globalArgs, err := operatorGlobalArgs(input.Key, input.Addr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	args := append(globalArgs, "module", input.AgentID, input.Module)
	if input.Config != "" {
		args = append(args, strings.Fields(input.Config)...)
	}

	result, err := t.exec.Run(ctx, "kubedagger-operator", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger operator module failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Operator Module: %s\n\n", input.Module)
	if output == "" {
		sb.WriteString("Task queued.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Operator Tasks

type OperatorTasksInput struct {
	Key     string `json:"key,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Action  string `json:"action"`
	AgentID string `json:"agent_id,omitempty"`
	TaskID  string `json:"task_id,omitempty"`
}

type OperatorTasksTool struct {
	exec executor.Executor
}

func NewOperatorTasks(exec executor.Executor) *OperatorTasksTool {
	return &OperatorTasksTool{exec: exec}
}

func (t *OperatorTasksTool) Name() string { return "kubedagger_operator_tasks" }

func (t *OperatorTasksTool) Description() string {
	return "List asynchronous tasks dispatched to a KubeDagger agent, or check the status of a specific task by ID. Use action 'list' with agent_id for the task table, or action 'status' with task_id for a single task."
}

func (t *OperatorTasksTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"key": {
				"type": "string",
				"description": "Operator API key (required; falls back to KUBEDAGGER_OPERATOR_KEY env var)"
			},
			"addr": {
				"type": "string",
				"description": "Operator address (default: 127.0.0.1:9443)"
			},
			"action": {
				"type": "string",
				"enum": ["list", "status"],
				"description": "list: tasks for an agent; status: single task by ID"
			},
			"agent_id": {
				"type": "string",
				"description": "Agent ID (required for action=list)"
			},
			"task_id": {
				"type": "string",
				"description": "Task ID (required for action=status)"
			}
		},
		"required": ["key", "action"]
	}`)
}

func (t *OperatorTasksTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorTasksInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.TaskID, "task_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	globalArgs, err := operatorGlobalArgs(input.Key, input.Addr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "status":
		if input.TaskID == "" {
			return errorResult("task_id is required for action=status"), nil
		}
		args = append(globalArgs, "status", input.TaskID)
	case "list":
		if input.AgentID == "" {
			return errorResult("agent_id is required for action=list"), nil
		}
		args = append(globalArgs, "tasks", input.AgentID)
	default:
		return errorResult("invalid action: must be 'list' or 'status'"), nil
	}

	result, err := t.exec.Run(ctx, "kubedagger-operator", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger operator tasks failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Operator Tasks: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No tasks found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
