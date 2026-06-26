package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DockerListInput struct {
	Namespace string `json:"namespace,omitempty"`
	All       bool   `json:"all,omitempty"`
}

type DockerListTool struct {
	exec executor.Executor
}

func NewDockerList(exec executor.Executor) *DockerListTool {
	return &DockerListTool{exec: exec}
}

func (t *DockerListTool) Name() string { return "kubedagger_docker_list" }

func (t *DockerListTool) Description() string {
	return "List containers visible from the current node using eBPF hooks on the container runtime. Shows container IDs, images, namespaces, and resource allocations without querying the Docker/containerd API directly."
}

func (t *DockerListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"namespace": {
				"type": "string",
				"description": "Filter by Kubernetes namespace"
			},
			"all": {
				"type": "boolean",
				"description": "Show all containers including stopped ones"
			}
		}
	}`)
}

func (t *DockerListTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DockerListInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"docker", "list"}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.All {
		args = append(args, "--all")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger docker list failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Docker List\n\n")
	if output == "" {
		sb.WriteString("No containers found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

type DockerOverrideInput struct {
	ContainerID string `json:"container_id"`
	Image       string `json:"image,omitempty"`
	Entrypoint  string `json:"entrypoint,omitempty"`
	Env         string `json:"env,omitempty"`
}

type DockerOverrideTool struct {
	exec executor.Executor
}

func NewDockerOverride(exec executor.Executor) *DockerOverrideTool {
	return &DockerOverrideTool{exec: exec}
}

func (t *DockerOverrideTool) Name() string { return "kubedagger_docker_override" }

func (t *DockerOverrideTool) Description() string {
	return "Override container configuration at the runtime level using eBPF hooks on containerd/CRI-O. Can modify image references, entrypoints, and environment variables at container creation time."
}

func (t *DockerOverrideTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container_id": {
				"type": "string",
				"description": "Target container ID or name"
			},
			"image": {
				"type": "string",
				"description": "Override image reference"
			},
			"entrypoint": {
				"type": "string",
				"description": "Override entrypoint command"
			},
			"env": {
				"type": "string",
				"description": "Environment variables to inject (KEY=VALUE format, comma-separated)"
			}
		},
		"required": ["container_id"]
	}`)
}

func (t *DockerOverrideTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DockerOverrideInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.ContainerID, "container_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Entrypoint, "entrypoint"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Env, "env"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"docker", "override", "--id", input.ContainerID}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
	}
	if input.Entrypoint != "" {
		args = append(args, "--entrypoint", input.Entrypoint)
	}
	if input.Env != "" {
		args = append(args, "--env", input.Env)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger docker override failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Docker Override: %s\n\n", input.ContainerID)
	if output == "" {
		sb.WriteString("Override applied.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
