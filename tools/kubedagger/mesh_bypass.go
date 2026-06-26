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
	Mesh      string `json:"mesh"`
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port,omitempty"`
	Method    string `json:"method,omitempty"`
	SkipMTLS  bool   `json:"skip_mtls,omitempty"`
}

type MeshBypassTool struct {
	exec executor.Executor
}

func NewMeshBypass(exec executor.Executor) *MeshBypassTool {
	return &MeshBypassTool{exec: exec}
}

func (t *MeshBypassTool) Name() string { return "kubedagger_mesh_bypass" }

func (t *MeshBypassTool) Description() string {
	return "Bypass service mesh (Istio, Linkerd, Cilium) mTLS enforcement and authorization policies by hooking the sidecar proxy's socket operations. Enables plaintext communication or impersonation of mesh identities."
}

func (t *MeshBypassTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mesh": {
				"type": "string",
				"enum": ["istio", "linkerd", "cilium", "auto"],
				"description": "Target service mesh"
			},
			"target": {
				"type": "string",
				"description": "Target service or pod to reach"
			},
			"port": {
				"type": "integer",
				"description": "Target port"
			},
			"method": {
				"type": "string",
				"enum": ["skip-sidecar", "impersonate", "plaintext", "cert-steal"],
				"description": "Bypass method"
			},
			"skip_mtls": {
				"type": "boolean",
				"description": "Skip mTLS verification entirely"
			}
		},
		"required": ["mesh"]
	}`)
}

func (t *MeshBypassTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MeshBypassInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"meshbypass", "--mesh", input.Mesh}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Method != "" {
		args = append(args, "--method", input.Method)
	}
	if input.SkipMTLS {
		args = append(args, "--skip-mtls")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger mesh bypass failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Service Mesh Bypass: %s\n\n", input.Mesh)
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
