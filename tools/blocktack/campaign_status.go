package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// maxProgressTail bounds how many JSON-lines progress events are echoed
// back per status call (the full stream stays in the stdout log file).
const maxProgressTail = 12

// CampaignStatusTool reports the live state of BlockTack campaigns: the
// BackgroundManager process status plus the JSON-lines step progress from
// the campaign's stdout file (started/step_started/step_finished/
// killchain/finished events) and, when the run directory is known, the
// crash-resilient status.json snapshot.
type CampaignStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewCampaignStatus constructs the blocktack_campaign_status tool.
func NewCampaignStatus(mgr *executor.BackgroundManager) *CampaignStatusTool {
	return &CampaignStatusTool{mgr: mgr}
}

func (t *CampaignStatusTool) Name() string { return "blocktack_campaign_status" }

func (t *CampaignStatusTool) Description() string {
	return "Report the state of BlockTack campaigns started with blocktack_campaign_start: running flag, PID, uptime, exit code, the run directory (from the first progress event), the last step events parsed from the JSON-lines progress stream, and the campaign's crash-resilient status.json snapshot when present. With no process_id, every managed blocktack campaign is listed." + authorizedUseNotice
}

func (t *CampaignStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by blocktack_campaign_start (omit to list all blocktack campaigns)"
			}
		}
	}`)
}

func (t *CampaignStatusTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateSafeString(input.ProcessID, "process_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	if input.ProcessID == "" {
		return t.listAll(), nil
	}
	status, err := t.mgr.Status(input.ProcessID)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	if status.Binary != blocktackBinary {
		return errorResult(fmt.Sprintf("process %s is a %s process, not a blocktack campaign", input.ProcessID, status.Binary)), nil
	}
	return campaignStatusResult(*status), nil
}

func (t *CampaignStatusTool) listAll() *mcp.ToolResult {
	campaigns := 0
	var sb strings.Builder
	sb.WriteString("## BlockTack Campaigns\n\n")
	for _, st := range t.mgr.List() {
		if st.Binary != blocktackBinary {
			continue
		}
		campaigns++
		state := "exited"
		if st.Running {
			state = "running"
		}
		fmt.Fprintf(&sb, "- **%s** — %s (pid %d, started %s)\n", st.ID, state, st.PID, st.StartedAt.Format(time.RFC3339))
	}
	if campaigns == 0 {
		sb.WriteString("No blocktack campaigns have been started in this server session.\n")
	}
	return textResult(sb.String())
}

// campaignStatusResult renders one campaign's process status plus the
// parsed progress tail and status.json snapshot.
func campaignStatusResult(status executor.BackgroundStatus) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString("## BlockTack Campaign Status\n\n")
	if status.Running {
		uptime := time.Since(status.StartedAt).Round(time.Second)
		fmt.Fprintf(&sb, "- **Status:** RUNNING (pid %d, uptime %s)\n", status.PID, uptime)
	} else {
		fmt.Fprintf(&sb, "- **Status:** EXITED (code %d, ended %s)\n", status.ExitCode, status.EndedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", status.ID)
	fmt.Fprintf(&sb, "- **Started:** %s\n", status.StartedAt.Format(time.RFC3339))

	// The first progress event carries the run directory.
	runDir := campaignRunDir(status.StdoutPath)
	if runDir != "" {
		fmt.Fprintf(&sb, "- **Run dir:** %s\n", runDir)
		if snap := readStatusSnapshot(runDir); snap != "" {
			sb.WriteString("\n### status.json snapshot\n\n```json\n" + snap + "\n```\n")
		}
	}

	if progress := campaignProgressTail(status.StdoutPath); progress != "" {
		sb.WriteString("\n### Recent progress events\n\n```json\n" + progress + "\n```\n")
	}
	if status.StdoutTruncated || status.StderrTruncated {
		sb.WriteString("\n- **Note:** process output streams were truncated at the 256 MiB cap.\n")
	}
	fmt.Fprintf(&sb, "\n- Progress stream: `%s`\n- Human log: `%s`\n", status.StdoutPath, status.StderrPath)
	return textResult(sb.String())
}

// campaignRunDir extracts the run directory from the first "started"
// event of the campaign's JSON-lines stdout file.
func campaignRunDir(stdoutPath string) string {
	if stdoutPath == "" {
		return ""
	}
	data, err := os.ReadFile(stdoutPath)
	if err != nil || len(data) == 0 {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event struct {
			Event  string `json:"event"`
			RunDir string `json:"run_dir"`
		}
		if json.Unmarshal([]byte(line), &event) == nil && event.RunDir != "" {
			return event.RunDir
		}
	}
	return ""
}

// campaignProgressTail returns the last maxProgressTail parseable
// JSON-lines events from the progress stream.
func campaignProgressTail(stdoutPath string) string {
	if stdoutPath == "" {
		return ""
	}
	data, err := os.ReadFile(stdoutPath)
	if err != nil {
		return ""
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var probe map[string]any
		if json.Unmarshal([]byte(line), &probe) != nil {
			continue // not a JSON event (binary noise, partial write)
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > maxProgressTail {
		lines = lines[len(lines)-maxProgressTail:]
	}
	return strings.Join(lines, "\n")
}

// readStatusSnapshot reads <run_dir>/status.json if present.
func readStatusSnapshot(runDir string) string {
	data, err := os.ReadFile(runDir + string(os.PathSeparator) + "status.json")
	if err != nil || len(data) == 0 {
		return ""
	}
	var pretty map[string]any
	if json.Unmarshal(data, &pretty) == nil {
		if out, err := json.MarshalIndent(pretty, "", "  "); err == nil {
			return string(out)
		}
	}
	return strings.TrimSpace(string(data))
}
