package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Execute tool

type ExecuteInput struct {
	SessionID string   `json:"session_id"`
	Command   string   `json:"command"`
	Args      []string `json:"args,omitempty"`
	Output    bool     `json:"output,omitempty"`
}

type ExecuteTool struct {
	exec executor.Executor
}

func NewExecute(exec executor.Executor) *ExecuteTool {
	return &ExecuteTool{exec: exec}
}

func (t *ExecuteTool) Name() string { return "sliver_execute" }

func (t *ExecuteTool) Description() string {
	return "Execute a command on a Sliver implant. Runs a binary on the remote system through an active session or beacon."
}

func (t *ExecuteTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"session_id": {
				"type": "string",
				"description": "Session or beacon ID to execute on"
			},
			"command": {
				"type": "string",
				"description": "Command/binary to execute"
			},
			"args": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Command arguments"
			},
			"output": {
				"type": "boolean",
				"description": "Capture output (default true)"
			}
		},
		"required": ["session_id", "command"]
	}`)
}

func (t *ExecuteTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ExecuteInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.Command, "command"); err != nil {
		return errorResult(err.Error()), nil
	}
	for i, a := range input.Args {
		if err := validateSafeString(a, fmt.Sprintf("args[%d]", i)); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"execute", "-s", input.SessionID, input.Command}
	args = append(args, input.Args...)
	if input.Output {
		args = append(args, "--output")
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver execute failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Sliver Execute\n\n")
	fmt.Fprintf(&sb, "**Command**: %s\n\n", input.Command)
	if output == "" {
		sb.WriteString("Command executed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Upload tool

type UploadInput struct {
	SessionID  string `json:"session_id"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
}

type UploadTool struct {
	exec executor.Executor
}

func NewUpload(exec executor.Executor) *UploadTool {
	return &UploadTool{exec: exec}
}

func (t *UploadTool) Name() string { return "sliver_upload" }

func (t *UploadTool) Description() string {
	return "Upload a file to a Sliver implant. Transfers a local file to the target system through an active session or beacon."
}

func (t *UploadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"session_id": {
				"type": "string",
				"description": "Session or beacon ID"
			},
			"local_path": {
				"type": "string",
				"description": "Local file path to upload"
			},
			"remote_path": {
				"type": "string",
				"description": "Remote destination path"
			}
		},
		"required": ["session_id", "local_path", "remote_path"]
	}`)
}

func (t *UploadTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input UploadInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.LocalPath, "local_path"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.RemotePath, "remote_path"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"upload", "-s", input.SessionID, input.LocalPath, input.RemotePath}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver upload failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Sliver Upload\n\n")
	fmt.Fprintf(&sb, "**Local**: %s → **Remote**: %s\n\n", input.LocalPath, input.RemotePath)
	if output == "" {
		sb.WriteString("Upload complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Download tool

type DownloadInput struct {
	SessionID  string `json:"session_id"`
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path,omitempty"`
}

type DownloadTool struct {
	exec executor.Executor
}

func NewDownload(exec executor.Executor) *DownloadTool {
	return &DownloadTool{exec: exec}
}

func (t *DownloadTool) Name() string { return "sliver_download" }

func (t *DownloadTool) Description() string {
	return "Download a file from a Sliver implant. Retrieves a remote file from the target system through an active session or beacon."
}

func (t *DownloadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"session_id": {
				"type": "string",
				"description": "Session or beacon ID"
			},
			"remote_path": {
				"type": "string",
				"description": "Remote file path to download"
			},
			"local_path": {
				"type": "string",
				"description": "Local destination path (optional)"
			}
		},
		"required": ["session_id", "remote_path"]
	}`)
}

func (t *DownloadTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DownloadInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.RemotePath, "remote_path"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.LocalPath, "local_path"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"download", "-s", input.SessionID, input.RemotePath}
	if input.LocalPath != "" {
		args = append(args, input.LocalPath)
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver download failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Sliver Download\n\n")
	fmt.Fprintf(&sb, "**Remote**: %s\n\n", input.RemotePath)
	if output == "" {
		sb.WriteString("Download complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
