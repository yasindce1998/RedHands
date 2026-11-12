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

// CorrelatorStatusTool reports the live state of protocol-correlator daemons
// started via telecom_correlator_start: one process by ID, or every managed
// correlator process (binary protocol-correlator) when no ID is given.
type CorrelatorStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewCorrelatorStatus constructs the telecom_correlator_status tool.
func NewCorrelatorStatus(mgr *executor.BackgroundManager) *CorrelatorStatusTool {
	return &CorrelatorStatusTool{mgr: mgr}
}

func (t *CorrelatorStatusTool) Name() string { return "telecom_correlator_status" }

func (t *CorrelatorStatusTool) Description() string {
	return "Report the state of StaticZero protocol correlators started with telecom_correlator_start: running flag, PID, uptime, exit code, output truncation, and log file paths (the stdout log holds the correlated threats). With no process_id, every managed protocol-correlator process is listed (other binaries such as staticzero-offense are not shown; use telecom_offense_status for those). Wraps StaticZero (eBPF telecom security research); authorized lab use only. Read-only query."
}

func (t *CorrelatorStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by telecom_correlator_start. Omit to list all managed protocol-correlator processes"
			}
		}
	}`)
}

func (t *CorrelatorStatusTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
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
			Content: []mcp.ContentBlock{{Type: "text", Text: renderCorrelatorStatuses([]executor.BackgroundStatus{*status})}},
		}, nil
	}

	var correlatorStatuses []executor.BackgroundStatus
	for _, st := range t.mgr.List() {
		if st.Binary == correlatorBinary {
			correlatorStatuses = append(correlatorStatuses, st)
		}
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderCorrelatorStatuses(correlatorStatuses)}},
	}, nil
}

// renderCorrelatorStatuses renders one or more correlator process states as
// markdown.
func renderCorrelatorStatuses(statuses []executor.BackgroundStatus) string {
	var sb strings.Builder
	sb.WriteString("## StaticZero Protocol Correlator Status\n\n")
	if len(statuses) == 0 {
		sb.WriteString("No managed protocol-correlator processes.\n")
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
			fmt.Fprintf(&sb, "- **Threat output (stdout):** %s\n", st.StdoutPath)
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
