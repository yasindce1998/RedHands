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
	SourcePod string `json:"source_pod,omitempty"`
	DestPod   string `json:"dest_pod,omitempty"`
	Mode      string `json:"mode,omitempty"`
}

type VethHijackTool struct {
	exec executor.Executor
}

func NewVethHijack(exec executor.Executor) *VethHijackTool {
	return &VethHijackTool{exec: exec}
}

func (t *VethHijackTool) Name() string { return "kubedagger_veth_hijack" }

func (t *VethHijackTool) Description() string {
	return "Hijack veth pairs connecting pod network namespaces to the host bridge. Attaches TC eBPF programs to mirror, redirect, or inject traffic between a source pod and a destination pod at the virtual ethernet level."
}

func (t *VethHijackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source_pod": {
				"type": "string",
				"description": "Source pod whose traffic is intercepted"
			},
			"dest_pod": {
				"type": "string",
				"description": "Destination pod for redirected/injected traffic"
			},
			"mode": {
				"type": "string",
				"enum": ["mirror", "redirect", "inject"],
				"description": "Hijack mode (default: mirror)"
			}
		}
	}`)
}

func (t *VethHijackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input VethHijackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.SourcePod, "source_pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.DestPod, "dest_pod"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"veth-hijack"}
	if input.SourcePod != "" {
		args = append(args, "--source-pod", input.SourcePod)
	}
	if input.DestPod != "" {
		args = append(args, "--dest-pod", input.DestPod)
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
		return errorResult(fmt.Sprintf("kubedagger veth-hijack failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Veth Hijack\n\n")
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
