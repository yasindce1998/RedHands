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
	Mode     string `json:"mode,omitempty"`
	DestIP   string `json:"dest_ip,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
}

type NetBypassTool struct {
	exec executor.Executor
}

func NewNetBypass(exec executor.Executor) *NetBypassTool {
	return &NetBypassTool{exec: exec}
}

func (t *NetBypassTool) Name() string { return "kubedagger_net_bypass" }

func (t *NetBypassTool) Description() string {
	return "Bypass Kubernetes NetworkPolicies using eBPF to reach blocked destinations. Sends traffic directly, encapsulates it inside allowed flows, or rewrites packet headers at the kernel level so isolated pods can communicate."
}

func (t *NetBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["direct", "encap", "rewrite"],
				"description": "Bypass mode (default: direct)"
			},
			"dest_ip": {
				"type": "string",
				"description": "Destination IP address to reach"
			},
			"dest_port": {
				"type": "integer",
				"description": "Destination port"
			}
		}
	}`)
}

func (t *NetBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateIP(input.DestIP); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"netbypass"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.DestIP != "" {
		args = append(args, "--dest-ip", input.DestIP)
	}
	if input.DestPort > 0 {
		args = append(args, "--dest-port", fmt.Sprintf("%d", input.DestPort))
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
	sb.WriteString("## KubeDagger Network Policy Bypass\n\n")
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
