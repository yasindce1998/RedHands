package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// DefenseStatusTool reports the live state of defense daemons started via
// this toolset: one process by ID, or every managed process when no ID is
// given (each entry names its binary, which may be another engine).
type DefenseStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewDefenseStatus constructs the telecom_defense_status tool.
func NewDefenseStatus(mgr *executor.BackgroundManager) *DefenseStatusTool {
	return &DefenseStatusTool{mgr: mgr}
}

func (t *DefenseStatusTool) Name() string { return "telecom_defense_status" }

func (t *DefenseStatusTool) Description() string {
	return "Report the state of StaticZero defense daemons started with telecom_defense_start: running flag, PID, uptime, exit code, output truncation, and alert/log file paths. With no process_id, every managed background process is listed (each entry shows its binary, which may be another engine such as aegis-shadow-defense). Wraps StaticZero (eBPF telecom security research); authorized lab use only. Read-only query."
}

func (t *DefenseStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by telecom_defense_start. Omit to list all managed background processes"
			}
		}
	}`)
}

func (t *DefenseStatusTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if input.ProcessID != "" {
		if err := validateSafeString(input.ProcessID, "process_id"); err != nil {
			return errorResult(err.Error()), nil
		}
		status, err := t.mgr.Status(input.ProcessID)
		if err != nil {
			return errorResult(err.Error()), nil
		}
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: renderDefenseStatuses("StaticZero Defense Daemon Status", []executor.BackgroundStatus{*status})}},
		}, nil
	}

	statuses := t.mgr.List()
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderDefenseStatuses("Managed Background Processes", statuses)}},
	}, nil
}

// renderDefenseStatuses renders one or more background process states as
// markdown.
func renderDefenseStatuses(title string, statuses []executor.BackgroundStatus) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n\n", title)
	if len(statuses) == 0 {
		sb.WriteString("No managed background processes.\n")
		return sb.String()
	}
	for _, st := range statuses {
		fmt.Fprintf(&sb, "### %s (%s)\n\n", st.ID, st.Binary)
		if st.Running {
			sb.WriteString("- **Running:** yes\n")
		} else {
			sb.WriteString("- **Running:** no\n")
		}
		fmt.Fprintf(&sb, "- **PID:** %d\n", st.PID)
		fmt.Fprintf(&sb, "- **Started:** %s\n", st.StartedAt.Format(time.RFC3339))
		if st.Running {
			fmt.Fprintf(&sb, "- **Uptime:** %s\n", time.Since(st.StartedAt).Round(time.Second))
		} else if !st.EndedAt.IsZero() {
			fmt.Fprintf(&sb, "- **Ended:** %s (ran %s)\n", st.EndedAt.Format(time.RFC3339), st.EndedAt.Sub(st.StartedAt).Round(time.Second))
			fmt.Fprintf(&sb, "- **Exit code:** %d\n", st.ExitCode)
		}
		if len(st.Args) > 0 {
			fmt.Fprintf(&sb, "- **Command:** %s %s\n", st.Binary, strings.Join(st.Args, " "))
		}
		if st.StdoutPath != "" {
			fmt.Fprintf(&sb, "- **SIEM alerts/output (stdout):** %s\n", st.StdoutPath)
		}
		if st.StderrPath != "" {
			fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", st.StderrPath)
		}
		if st.StdoutTruncated {
			sb.WriteString("- **Stdout truncated:** yes (256 MiB cap reached; further output dropped)\n")
		}
		if st.StderrTruncated {
			sb.WriteString("- **Stderr truncated:** yes (256 MiB cap reached; further output dropped)\n")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
