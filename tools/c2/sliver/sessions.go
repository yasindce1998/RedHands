package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SessionsInput struct {
	Action    string `json:"action"`
	SessionID string `json:"session_id,omitempty"`
}

type SessionsTool struct {
	exec executor.Executor
}

func NewSessions(exec executor.Executor) *SessionsTool {
	return &SessionsTool{exec: exec}
}

func (t *SessionsTool) Name() string { return "sliver_sessions" }

func (t *SessionsTool) Description() string {
	return "List and interact with active Sliver C2 sessions. Sessions maintain persistent connections to implants for real-time command execution."
}

func (t *SessionsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "use", "kill"],
				"description": "Session action"
			},
			"session_id": {
				"type": "string",
				"description": "Session ID (required for use/kill)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SessionsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SessionsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.SessionID, "session_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"sessions"}
	case "use":
		if input.SessionID == "" {
			return errorResult("session_id is required for use action"), nil
		}
		args = []string{"use", "-s", input.SessionID}
	case "kill":
		if input.SessionID == "" {
			return errorResult("session_id is required for kill action"), nil
		}
		args = []string{"sessions", "--kill", input.SessionID}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver sessions failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Sliver Sessions: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No active sessions.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
