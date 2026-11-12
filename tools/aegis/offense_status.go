package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// OffenseStatusTool reports the live state of offense daemons started via
// aegis_offense_start: one process by ID, or every managed offense process
// (binary aegis-shadow-offense) when no ID is given.
type OffenseStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewOffenseStatus constructs the aegis_offense_status tool.
func NewOffenseStatus(mgr *executor.BackgroundManager) *OffenseStatusTool {
	return &OffenseStatusTool{mgr: mgr}
}

func (t *OffenseStatusTool) Name() string { return "aegis_offense_status" }

func (t *OffenseStatusTool) Description() string {
	return "Report the state of Aegis-Shadow offense rootkit loaders started with aegis_offense_start: running flag, PID, uptime, exit code, output truncation, and log file paths. With no process_id, every managed aegis-shadow-offense process is listed (other binaries such as aegis-shadow-defense are not shown; use aegis_defense_status for those). Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Read-only query."
}

func (t *OffenseStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by aegis_offense_start. Omit to list all managed aegis-shadow-offense processes"
			}
		}
	}`)
}

func (t *OffenseStatusTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
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
			Content: []mcp.ContentBlock{{Type: "text", Text: renderOffenseStatuses([]executor.BackgroundStatus{*status})}},
		}, nil
	}

	var offenseStatuses []executor.BackgroundStatus
	for _, st := range t.mgr.List() {
		if st.Binary == offenseBinary {
			offenseStatuses = append(offenseStatuses, st)
		}
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderOffenseStatuses(offenseStatuses)}},
	}, nil
}

// renderOffenseStatuses renders one or more offense process states as
// markdown.
func renderOffenseStatuses(statuses []executor.BackgroundStatus) string {
	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Offense Loader Status\n\n")
	if len(statuses) == 0 {
		sb.WriteString("No managed aegis-shadow-offense processes.\n")
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
			fmt.Fprintf(&sb, "- **Loader output (stdout):** %s\n", st.StdoutPath)
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
