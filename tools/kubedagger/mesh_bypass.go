package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type MeshBypassInput struct {
	Mode       string `json:"mode,omitempty"`
	MeshTarget string `json:"mesh_target,omitempty"`
}

type MeshBypassTool struct {
	exec executor.Executor
}

func NewMeshBypass(exec executor.Executor) *MeshBypassTool {
	return &MeshBypassTool{exec: exec}
}

func (t *MeshBypassTool) Name() string { return "kubedagger_mesh_bypass" }

func (t *MeshBypassTool) Description() string {
	return "Bypass service mesh (Istio, Linkerd) sidecar enforcement by hooking the proxy's socket operations. Skips the sidecar proxy for outbound traffic, spoofs mesh identities, or falls back to raw connections, evading mTLS and authorization policies."
}

func (t *MeshBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["skip-proxy", "spoof-identity", "raw-connect"],
				"description": "Bypass mode (default: skip-proxy)"
			},
			"mesh_target": {
				"type": "string",
				"description": "Target service or pod to reach through the mesh"
			}
		}
	}`)
}

func (t *MeshBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MeshBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.MeshTarget, "mesh_target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"meshbypass"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.MeshTarget != "" {
		args = append(args, "--mesh-target", input.MeshTarget)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger meshbypass failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Service Mesh Bypass\n\n")
	if output == "" {
		sb.WriteString("Mesh bypass active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
