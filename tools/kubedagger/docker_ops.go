package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DockerListInput struct{}

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
		"properties": {}
	}`)
}

func (t *DockerListTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DockerListInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"docker", "list"}

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

// validateDockerName enforces the docker put/delete --from/--to constraints:
// max 63 chars and no '#' character (empty allowed only when not required).
func validateDockerName(s, field string) error {
	if s == "" {
		return nil
	}
	if len(s) > 63 {
		return fmt.Errorf("%s too long (max 63 chars)", field)
	}
	if strings.Contains(s, "#") {
		return fmt.Errorf("%s must not contain '#'", field)
	}
	return nil
}

type DockerOverrideInput struct {
	Action   string `json:"action,omitempty"`
	From     string `json:"from"`
	To       string `json:"to,omitempty"`
	Override int    `json:"override,omitempty"`
	Ping     int    `json:"ping,omitempty"`
}

type DockerOverrideTool struct {
	exec executor.Executor
}

func NewDockerOverride(exec executor.Executor) *DockerOverrideTool {
	return &DockerOverrideTool{exec: exec}
}

func (t *DockerOverrideTool) Name() string { return "kubedagger_docker_override" }

func (t *DockerOverrideTool) Description() string {
	return "Override OCI image references at the container runtime level via 'docker put': swap a source image reference (--from) for a destination one (--to) in container creation, optionally replacing existing mappings (--override=1) or manipulating the ping handler (--ping: 0=nop, 1=crash, 2=run, 3=hide). Action 'delete' removes a mapping via 'docker delete --from'."
}

func (t *DockerOverrideTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["put", "delete"],
				"description": "put: create/replace an image override mapping; delete: remove one (default: put)"
			},
			"from": {
				"type": "string",
				"description": "Source image reference to override (required, max 63 chars, no '#')"
			},
			"to": {
				"type": "string",
				"description": "Replacement image reference (put only, max 63 chars, no '#')"
			},
			"override": {
				"type": "integer",
				"enum": [0, 1],
				"description": "put only: 0=keep existing mapping (nop), 1=replace it (default: 0)"
			},
			"ping": {
				"type": "integer",
				"enum": [0, 1, 2, 3],
				"description": "put only: ping handler behavior — 0=nop, 1=crash, 2=run, 3=hide (default: 0)"
			}
		},
		"required": ["from"]
	}`)
}

func (t *DockerOverrideTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DockerOverrideInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.From == "" {
		return errorResult("from is required"), nil
	}
	if err := validateSafeString(input.From, "from"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateDockerName(input.From, "from"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.To, "to"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateDockerName(input.To, "to"); err != nil {
		return errorResult(err.Error()), nil
	}

	action := input.Action
	if action == "" {
		action = "put"
	}
	switch action {
	case "put":
		if input.Override < 0 || input.Override > 1 {
			return errorResult("override must be 0 or 1"), nil
		}
		if input.Ping < 0 || input.Ping > 3 {
			return errorResult("ping must be 0, 1, 2, or 3"), nil
		}
	case "delete":
		// --from only
	default:
		return errorResult("invalid action: must be 'put' or 'delete'"), nil
	}

	args := []string{"docker", action, "--from", input.From}
	if action == "put" {
		if input.To != "" {
			args = append(args, "--to", input.To)
		}
		args = append(args, "--override", fmt.Sprintf("%d", input.Override))
		args = append(args, "--ping", fmt.Sprintf("%d", input.Ping))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger docker %s failed: %s\n%s", action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Docker %s: %s\n\n", action, input.From)
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
