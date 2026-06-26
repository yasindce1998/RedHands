package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type NetBypassInput struct {
	Target    string `json:"target"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Interface string `json:"interface,omitempty"`
	Method    string `json:"method,omitempty"`
}

type NetBypassTool struct {
	exec executor.Executor
}

func NewNetBypass(exec executor.Executor) *NetBypassTool {
	return &NetBypassTool{exec: exec}
}

func (t *NetBypassTool) Name() string { return "kubedagger_net_bypass" }

func (t *NetBypassTool) Description() string {
	return "Bypass Kubernetes NetworkPolicies using eBPF TC (traffic control) hooks to rewrite packet headers at the kernel level. Enables communication between pods that should be network-isolated according to policy."
}

func (t *NetBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP or pod to reach through network policy"
			},
			"port": {
				"type": "integer",
				"description": "Target port"
			},
			"protocol": {
				"type": "string",
				"enum": ["tcp", "udp"],
				"description": "Protocol to use"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to hook"
			},
			"method": {
				"type": "string",
				"enum": ["tc-rewrite", "xdp-redirect", "raw-socket"],
				"description": "Bypass technique to use"
			}
		},
		"required": ["target"]
	}`)
}

func (t *NetBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"netbypass", "--target", input.Target}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Protocol != "" {
		args = append(args, "--protocol", input.Protocol)
	}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.Method != "" {
		args = append(args, "--method", input.Method)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger netbypass failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Network Policy Bypass: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("Bypass established.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
