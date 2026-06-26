package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Scheduler Starve

type SchedStarveInput struct {
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Intensity string `json:"intensity,omitempty"`
}

type SchedStarveTool struct {
	exec executor.Executor
}

func NewSchedStarve(exec executor.Executor) *SchedStarveTool {
	return &SchedStarveTool{exec: exec}
}

func (t *SchedStarveTool) Name() string { return "kubedagger_sched_starve" }

func (t *SchedStarveTool) Description() string {
	return "Starve specific pods of CPU by manipulating the CFS scheduler via eBPF. Hooks sched_process_exec and sched_switch to artificially deprioritize target processes without modifying cgroup limits."
}

func (t *SchedStarveTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["start", "stop", "status"],
				"description": "Scheduler manipulation action"
			},
			"target": {
				"type": "string",
				"description": "Target pod or process name"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			},
			"intensity": {
				"type": "string",
				"enum": ["low", "medium", "high", "total"],
				"description": "Starvation intensity"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SchedStarveTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SchedStarveInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sched-starve", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Intensity != "" {
		args = append(args, "--intensity", input.Intensity)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger sched-starve failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Sched Starve: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Starvation active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Fault Inject

type FaultInjectInput struct {
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	FaultType string `json:"fault_type,omitempty"`
	Rate      int    `json:"rate,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type FaultInjectTool struct {
	exec executor.Executor
}

func NewFaultInject(exec executor.Executor) *FaultInjectTool {
	return &FaultInjectTool{exec: exec}
}

func (t *FaultInjectTool) Name() string { return "kubedagger_fault_inject" }

func (t *FaultInjectTool) Description() string {
	return "Inject faults into running processes by hooking syscalls. Can cause random IO errors, network timeouts, memory allocation failures, and permission denied errors to destabilize target services."
}

func (t *FaultInjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["start", "stop", "status"],
				"description": "Fault injection action"
			},
			"target": {
				"type": "string",
				"description": "Target pod or process"
			},
			"fault_type": {
				"type": "string",
				"enum": ["io-error", "net-timeout", "mem-fail", "perm-denied", "random"],
				"description": "Type of fault to inject"
			},
			"rate": {
				"type": "integer",
				"description": "Fault rate percentage (1-100)"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			}
		},
		"required": ["action"]
	}`)
}

func (t *FaultInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FaultInjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"fault-inject", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.FaultType != "" {
		args = append(args, "--fault-type", input.FaultType)
	}
	if input.Rate > 0 {
		args = append(args, "--rate", fmt.Sprintf("%d", input.Rate))
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger fault-inject failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Fault Inject: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Fault injection active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Cgroup Manip

type CgroupManipInput struct {
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Limit     string `json:"limit,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type CgroupManipTool struct {
	exec executor.Executor
}

func NewCgroupManip(exec executor.Executor) *CgroupManipTool {
	return &CgroupManipTool{exec: exec}
}

func (t *CgroupManipTool) Name() string { return "kubedagger_cgroup_manip" }

func (t *CgroupManipTool) Description() string {
	return "Manipulate cgroup settings of running containers to cause OOM kills, CPU throttling, or IO starvation. Modifies cgroup parameters directly via eBPF, bypassing kubelet's resource management."
}

func (t *CgroupManipTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["throttle", "oom", "io-starve", "restore", "status"],
				"description": "Cgroup manipulation action"
			},
			"target": {
				"type": "string",
				"description": "Target pod or container"
			},
			"resource": {
				"type": "string",
				"enum": ["cpu", "memory", "io", "pids"],
				"description": "Resource to manipulate"
			},
			"limit": {
				"type": "string",
				"description": "New limit value"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			}
		},
		"required": ["action"]
	}`)
}

func (t *CgroupManipTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CgroupManipInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Limit, "limit"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cgroup-manip", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Resource != "" {
		args = append(args, "--resource", input.Resource)
	}
	if input.Limit != "" {
		args = append(args, "--limit", input.Limit)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger cgroup-manip failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Cgroup Manip: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Manipulation active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Election Disrupt

type ElectionDisruptInput struct {
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type ElectionDisruptTool struct {
	exec executor.Executor
}

func NewElectionDisrupt(exec executor.Executor) *ElectionDisruptTool {
	return &ElectionDisruptTool{exec: exec}
}

func (t *ElectionDisruptTool) Name() string { return "kubedagger_election_disrupt" }

func (t *ElectionDisruptTool) Description() string {
	return "Disrupt Kubernetes leader election by intercepting and manipulating lease objects. Forces leader failovers, causes split-brain, or permanently prevents election convergence for HA controllers."
}

func (t *ElectionDisruptTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["disrupt", "force-failover", "split-brain", "block", "status"],
				"description": "Election disruption action"
			},
			"target": {
				"type": "string",
				"description": "Target controller or lease name"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace of the lease object"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ElectionDisruptTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ElectionDisruptInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"election-disrupt", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger election-disrupt failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Election Disrupt: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Disruption active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
