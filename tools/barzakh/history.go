package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var historyActions = []string{"list", "show", "diff", "trends"}

// HistoryTool wraps `barzakh-scanner history list|show|diff|trends`
// (verified against scanner main.rs):
//
//	history list [--db <sqlite>] [--limit <n>]
//	history show <id> [--db <sqlite>]
//	history diff <a> <b> [--db <sqlite>]
//	history trends [--db <sqlite>]
//
// id, a and b are POSITIONAL arguments (scan record ids); --db defaults to
// barzakh-history.sqlite in the CLI. All actions are read-only SQLite
// queries; the scanner main() exits 2 on error, so no detection-exit
// handling is needed.
type HistoryInput struct {
	Action string `json:"action"`
	DB     string `json:"db,omitempty"`
	Limit  string `json:"limit,omitempty"`
	ID     string `json:"id,omitempty"`
	A      string `json:"a,omitempty"`
	B      string `json:"b,omitempty"`
}

type HistoryTool struct {
	exec executor.Executor
}

func NewHistory(exec executor.Executor) *HistoryTool {
	return &HistoryTool{exec: exec}
}

func (t *HistoryTool) Name() string { return "barzakh_history" }

func (t *HistoryTool) Description() string {
	return "Browse the recorded scan history SQLite database (populated via barzakh-scanner scan --history): list recent scans newest first, show one scan record with its findings, diff two scans (new vs resolved findings), or aggregate daily trends. Read-only queries."
}

func (t *HistoryTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "show", "diff", "trends"],
				"description": "list recent scans, show one scan record, diff two scans, or show daily trends"
			},
			"db": {
				"type": "string",
				"description": "History database path (default: barzakh-history.sqlite)"
			},
			"limit": {
				"type": "string",
				"description": "Maximum number of scans to show (list only; default: 20)"
			},
			"id": {
				"type": "string",
				"description": "Scan id (required for show)"
			},
			"a": {
				"type": "string",
				"description": "Older scan id (required for diff)"
			},
			"b": {
				"type": "string",
				"description": "Newer scan id (required for diff)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *HistoryTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HistoryInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if !isValidAction(historyActions, input.Action) {
		return errorResult("invalid action: must be one of " + strings.Join(historyActions, ", ")), nil
	}
	if err := validatePath(input.DB, "db"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.Limit, "limit"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.ID, "id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.A, "a"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt(input.B, "b"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"history", "list"}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
		if input.Limit != "" {
			args = append(args, "--limit", input.Limit)
		}
	case "show":
		if input.ID == "" {
			return errorResult("id is required for show"), nil
		}
		args = []string{"history", "show", input.ID}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "diff":
		if input.A == "" || input.B == "" {
			return errorResult("a and b are required for diff"), nil
		}
		args = []string{"history", "diff", input.A, input.B}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "trends":
		args = []string{"history", "trends"}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner history %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Scan History: %s\n\n", input.Action)
	if input.DB != "" {
		fmt.Fprintf(&sb, "- **DB:** %s\n", input.DB)
	}
	switch input.Action {
	case "list":
		if input.Limit != "" {
			fmt.Fprintf(&sb, "- **Limit:** %s\n", input.Limit)
		}
	case "show":
		fmt.Fprintf(&sb, "- **Scan id:** %s\n", input.ID)
	case "diff":
		fmt.Fprintf(&sb, "- **Diff:** #%s → #%s\n", input.A, input.B)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("History query completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
