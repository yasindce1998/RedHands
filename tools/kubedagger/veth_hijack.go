package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type VethHijackInput struct {
	Action    string `json:"action"`
	Interface string `json:"interface,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Duration  int    `json:"duration,omitempty"`
}

type VethHijackTool struct {
	exec executor.Executor
}

func NewVethHijack(exec executor.Executor) *VethHijackTool {
	return &VethHijackTool{exec: exec}
}

func (t *VethHijackTool) Name() string { return "kubedagger_veth_hijack" }

func (t *VethHijackTool) Description() string {
	return "Hijack veth pairs connecting pod network namespaces to the host bridge. Attaches TC eBPF programs to intercept, modify, or redirect traffic between containers at the virtual ethernet level."
}

func (t *VethHijackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["sniff", "redirect", "inject", "mirror", "status"],
				"description": "Hijack action"
			},
			"interface": {
				"type": "string",
				"description": "Veth interface name (e.g., vethXXXX)"
			},
			"pod": {
				"type": "string",
				"description": "Target pod (auto-resolves veth)"
			},
			"namespace": {
				"type": "string",
				"description": "Target pod namespace"
			},
			"duration": {
				"type": "integer",
				"description": "Capture/redirect duration in seconds"
			}
		},
		"required": ["action"]
	}`)
}

func (t *VethHijackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input VethHijackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"veth-hijack", "--action", input.Action}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Duration > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", input.Duration))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger veth-hijack failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Veth Hijack: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Hijack active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
