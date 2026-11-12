package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FSWatchInput struct {
	Action      string `json:"action"`
	Path        string `json:"path"`
	InContainer bool   `json:"in_container,omitempty"`
	Active      bool   `json:"active,omitempty"`
}

type FSWatchTool struct {
	exec executor.Executor
}

func NewFSWatch(exec executor.Executor) *FSWatchTool {
	return &FSWatchTool{exec: exec}
}

func (t *FSWatchTool) Name() string { return "kubedagger_fs_watch" }

func (t *FSWatchTool) Description() string {
	return "Manage eBPF-based file system watchers. 'add' begins watching a path (optionally inside a container, or only while active), 'delete' removes the watcher, and 'get' dumps the content captured for the path."
}

func (t *FSWatchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["add", "delete", "get"],
				"description": "Watcher action"
			},
			"path": {
				"type": "string",
				"description": "File system path to watch (required, positional)"
			},
			"in_container": {
				"type": "boolean",
				"description": "Resolve the path inside the current container"
			},
			"active": {
				"type": "boolean",
				"description": "Only capture while the path is actively being modified"
			}
		},
		"required": ["action", "path"]
	}`)
}

func (t *FSWatchTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FSWatchInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Action == "" {
		return errorResult("action is required"), nil
	}
	switch input.Action {
	case "add", "delete", "get":
	default:
		return errorResult("invalid action: must be 'add', 'delete', or 'get'"), nil
	}
	if input.Path == "" {
		return errorResult("path is required"), nil
	}
	if err := validateSafeString(input.Path, "path"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"fs_watch", input.Action, input.Path}
	if input.InContainer {
		args = append(args, "--in-container")
	}
	if input.Active {
		args = append(args, "--active")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger fs_watch %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger FS Watch: %s\n\n", input.Action)
	fmt.Fprintf(&sb, "Path: %s\n\n", input.Path)
	if output == "" {
		sb.WriteString("Operation completed (no content).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
