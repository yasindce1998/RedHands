package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CRITamperInput struct {
	Action    string `json:"action"`
	Container string `json:"container,omitempty"`
	Runtime   string `json:"runtime,omitempty"`
	Config    string `json:"config,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type CRITamperTool struct {
	exec executor.Executor
}

func NewCRITamper(exec executor.Executor) *CRITamperTool {
	return &CRITamperTool{exec: exec}
}

func (t *CRITamperTool) Name() string { return "kubedagger_cri_tamper" }

func (t *CRITamperTool) Description() string {
	return "Tamper with the Container Runtime Interface (CRI) by hooking gRPC calls between kubelet and containerd/CRI-O. Can modify container creation requests to escalate privileges, disable security profiles, or inject capabilities."
}

func (t *CRITamperTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["escalate", "disable-seccomp", "add-caps", "modify-mount", "status"],
				"description": "CRI tampering action"
			},
			"container": {
				"type": "string",
				"description": "Target container ID or name pattern"
			},
			"runtime": {
				"type": "string",
				"enum": ["containerd", "crio", "auto"],
				"description": "Container runtime to target"
			},
			"config": {
				"type": "string",
				"description": "Configuration override (JSON)"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace for filtering"
			}
		},
		"required": ["action"]
	}`)
}

func (t *CRITamperTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CRITamperInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Container, "container"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Config, "config"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cri-tamper", "--action", input.Action}
	if input.Container != "" {
		args = append(args, "--container", input.Container)
	}
	if input.Runtime != "" {
		args = append(args, "--runtime", input.Runtime)
	}
	if input.Config != "" {
		args = append(args, "--config", input.Config)
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
		return errorResult(fmt.Sprintf("kubedagger cri-tamper failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger CRI Tamper: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Tamper active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
