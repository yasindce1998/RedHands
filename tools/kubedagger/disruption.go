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
	TargetCgroup string `json:"target_cgroup,omitempty"`
	Intensity    string `json:"intensity,omitempty"`
}

type SchedStarveTool struct {
	exec executor.Executor
}

func NewSchedStarve(exec executor.Executor) *SchedStarveTool {
	return &SchedStarveTool{exec: exec}
}

func (t *SchedStarveTool) Name() string { return "kubedagger_sched_starve" }

func (t *SchedStarveTool) Description() string {
	return "Starve workloads in a target cgroup of CPU by manipulating the CFS scheduler via eBPF. Hooks sched_switch to artificially deprioritize target processes without modifying cgroup limits."
}

func (t *SchedStarveTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target_cgroup": {
				"type": "string",
				"description": "Target cgroup path (e.g. '/kubepods/burstable/pod123')"
			},
			"intensity": {
				"type": "string",
				"enum": ["low", "medium", "high"],
				"description": "Starvation intensity (default: medium)"
			}
		}
	}`)
}

func (t *SchedStarveTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SchedStarveInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetCgroup, "target_cgroup"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sched-starve"}
	if input.TargetCgroup != "" {
		args = append(args, "--target-cgroup", input.TargetCgroup)
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
	sb.WriteString("## KubeDagger Sched Starve\n\n")
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
	TargetPids string `json:"target_pids,omitempty"`
	Syscalls   string `json:"syscalls,omitempty"`
	ErrorRate  string `json:"error_rate,omitempty"`
	Errno      string `json:"errno,omitempty"`
}

type FaultInjectTool struct {
	exec executor.Executor
}

func NewFaultInject(exec executor.Executor) *FaultInjectTool {
	return &FaultInjectTool{exec: exec}
}

func (t *FaultInjectTool) Name() string { return "kubedagger_fault_inject" }

func (t *FaultInjectTool) Description() string {
	return "Inject faults into running processes by hooking syscalls. Causes targeted syscalls from the given PIDs to fail at the configured rate with the chosen errno, destabilizing services with plausible IO or network errors."
}

func (t *FaultInjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target_pids": {
				"type": "string",
				"description": "Comma-separated list of target process IDs (e.g. '1234,5678')"
			},
			"syscalls": {
				"type": "string",
				"description": "Comma-separated syscalls to fail (default: read,write,connect)"
			},
			"error_rate": {
				"type": "string",
				"description": "Percentage of calls to fail, '0'-'100' (default: 25)"
			},
			"errno": {
				"type": "string",
				"description": "Errno to return for injected failures (default: EIO)"
			}
		}
	}`)
}

func (t *FaultInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FaultInjectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePIDList(input.TargetPids); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Syscalls, "syscalls"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ErrorRate, "error_rate"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Errno, "errno"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"fault-inject"}
	if input.TargetPids != "" {
		args = append(args, "--target-pids", input.TargetPids)
	}
	if input.Syscalls != "" {
		args = append(args, "--syscalls", input.Syscalls)
	}
	if input.ErrorRate != "" {
		args = append(args, "--error-rate", input.ErrorRate)
	}
	if input.Errno != "" {
		args = append(args, "--errno", input.Errno)
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
	sb.WriteString("## KubeDagger Fault Inject\n\n")
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
	TargetPod string `json:"target_pod,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Action    string `json:"action,omitempty"`
}

type CgroupManipTool struct {
	exec executor.Executor
}

func NewCgroupManip(exec executor.Executor) *CgroupManipTool {
	return &CgroupManipTool{exec: exec}
}

func (t *CgroupManipTool) Name() string { return "kubedagger_cgroup_manip" }

func (t *CgroupManipTool) Description() string {
	return "Manipulate cgroup settings of running pods to cause resource starvation or termination. Limits memory/CPU, freezes processes, or triggers OOM kills by modifying cgroup parameters directly, bypassing kubelet resource management."
}

func (t *CgroupManipTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target_pod": {
				"type": "string",
				"description": "Target pod whose cgroup is manipulated"
			},
			"resource": {
				"type": "string",
				"enum": ["memory", "cpu"],
				"description": "Resource to manipulate (default: memory)"
			},
			"action": {
				"type": "string",
				"enum": ["limit", "freeze", "kill"],
				"description": "Cgroup action (default: limit)"
			}
		}
	}`)
}

func (t *CgroupManipTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CgroupManipInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.TargetPod, "target_pod"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cgroup-manip"}
	if input.TargetPod != "" {
		args = append(args, "--target-pod", input.TargetPod)
	}
	if input.Resource != "" {
		args = append(args, "--resource", input.Resource)
	}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
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
	sb.WriteString("## KubeDagger Cgroup Manip\n\n")
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
	Target string `json:"target,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type ElectionDisruptTool struct {
	exec executor.Executor
}

func NewElectionDisrupt(exec executor.Executor) *ElectionDisruptTool {
	return &ElectionDisruptTool{exec: exec}
}

func (t *ElectionDisruptTool) Name() string { return "kubedagger_election_disrupt" }

func (t *ElectionDisruptTool) Description() string {
	return "Disrupt Kubernetes leader election by intercepting and manipulating lease objects. Steals leadership, denies election attempts, or oscillates leadership to force failovers and split-brain in HA controllers."
}

func (t *ElectionDisruptTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"enum": ["scheduler", "controller-manager", "custom"],
				"description": "Election target (default: scheduler)"
			},
			"mode": {
				"type": "string",
				"enum": ["steal", "deny", "oscillate"],
				"description": "Disruption mode (default: deny)"
			}
		}
	}`)
}

func (t *ElectionDisruptTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ElectionDisruptInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"election-disrupt"}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
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
	sb.WriteString("## KubeDagger Election Disrupt\n\n")
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
