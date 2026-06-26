package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Operator Agents

type OperatorAgentsInput struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id,omitempty"`
	Filter  string `json:"filter,omitempty"`
}

type OperatorAgentsTool struct {
	exec executor.Executor
}

func NewOperatorAgents(exec executor.Executor) *OperatorAgentsTool {
	return &OperatorAgentsTool{exec: exec}
}

func (t *OperatorAgentsTool) Name() string { return "kubedagger_operator_agents" }

func (t *OperatorAgentsTool) Description() string {
	return "Manage KubeDagger agents via the operator. List, inspect, connect to, or remove deployed eBPF agents across the cluster."
}

func (t *OperatorAgentsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "inspect", "connect", "remove", "deploy"],
				"description": "Agent management action"
			},
			"agent_id": {
				"type": "string",
				"description": "Agent ID for inspect/connect/remove"
			},
			"filter": {
				"type": "string",
				"description": "Filter agents by node, namespace, or status"
			}
		},
		"required": ["action"]
	}`)
}

func (t *OperatorAgentsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorAgentsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"agents", "--action", input.Action}
	if input.AgentID != "" {
		args = append(args, "--agent-id", input.AgentID)
	}
	if input.Filter != "" {
		args = append(args, "--filter", input.Filter)
	}

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
	fmt.Fprintf(&sb, "## KubeDagger Operator Agents: %s\n\n", input.Action)
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
	return "Execute shell commands on a remote KubeDagger agent via the operator C2 channel. Commands are tunneled through the covert channel and results returned asynchronously."
}

func (t *OperatorShellTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"agent_id": {
				"type": "string",
				"description": "Target agent ID"
			},
			"command": {
				"type": "string",
				"description": "Shell command to execute"
			}
		},
		"required": ["agent_id", "command"]
	}`)
}

func (t *OperatorShellTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorShellInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Command, "command"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"shell", "--agent-id", input.AgentID, "--command", input.Command}

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
		sb.WriteString("Command executed (no output).\n")
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
	Action  string `json:"action"`
	Module  string `json:"module,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
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
	return "Load, unload, or configure eBPF modules on remote agents. Modules provide specific capabilities (network interception, syscall hooking, etc.) and can be hot-swapped at runtime."
}

func (t *OperatorModuleTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["load", "unload", "list", "configure"],
				"description": "Module management action"
			},
			"module": {
				"type": "string",
				"description": "Module name"
			},
			"agent_id": {
				"type": "string",
				"description": "Target agent ID"
			},
			"config": {
				"type": "string",
				"description": "Module configuration (JSON)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *OperatorModuleTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorModuleInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Module, "module"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Config, "config"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"module", "--action", input.Action}
	if input.Module != "" {
		args = append(args, "--module", input.Module)
	}
	if input.AgentID != "" {
		args = append(args, "--agent-id", input.AgentID)
	}
	if input.Config != "" {
		args = append(args, "--config", input.Config)
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
	fmt.Fprintf(&sb, "## KubeDagger Operator Module: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
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
	Action  string `json:"action"`
	TaskID  string `json:"task_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
}

type OperatorTasksTool struct {
	exec executor.Executor
}

func NewOperatorTasks(exec executor.Executor) *OperatorTasksTool {
	return &OperatorTasksTool{exec: exec}
}

func (t *OperatorTasksTool) Name() string { return "kubedagger_operator_tasks" }

func (t *OperatorTasksTool) Description() string {
	return "Manage asynchronous tasks dispatched to KubeDagger agents. View pending, running, and completed tasks, retrieve results, or cancel operations."
}

func (t *OperatorTasksTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "result", "cancel", "status"],
				"description": "Task management action"
			},
			"task_id": {
				"type": "string",
				"description": "Task ID for result/cancel"
			},
			"agent_id": {
				"type": "string",
				"description": "Filter tasks by agent"
			}
		},
		"required": ["action"]
	}`)
}

func (t *OperatorTasksTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OperatorTasksInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TaskID, "task_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.AgentID, "agent_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"tasks", "--action", input.Action}
	if input.TaskID != "" {
		args = append(args, "--task-id", input.TaskID)
	}
	if input.AgentID != "" {
		args = append(args, "--agent-id", input.AgentID)
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
