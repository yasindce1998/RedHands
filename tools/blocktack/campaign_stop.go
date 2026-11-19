package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// CampaignStopTool stops a BlockTack campaign started with
// blocktack_campaign_start (SIGTERM to its process group, SIGKILL after
// five seconds). Stopping mid-run leaves status.json behind (written
// after every step) but findings.json only appears for completed runs.
type CampaignStopTool struct {
	mgr *executor.BackgroundManager
}

// NewCampaignStop constructs the blocktack_campaign_stop tool.
func NewCampaignStop(mgr *executor.BackgroundManager) *CampaignStopTool {
	return &CampaignStopTool{mgr: mgr}
}

func (t *CampaignStopTool) Name() string { return "blocktack_campaign_stop" }

func (t *CampaignStopTool) Description() string {
	return "Stop a BlockTack campaign started with blocktack_campaign_start (SIGTERM to its process group, SIGKILL after 5 seconds; anvil forks spawned by playbook shell steps are killed with it). Stopping an unknown process ID is an error; stopping an already-finished campaign is a no-op. A campaign stopped mid-run keeps its crash-resilient status.json, but findings.json is only written when a run completes." + authorizedUseNotice
}

func (t *CampaignStopTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by blocktack_campaign_start (proc_...)"
			}
		},
		"required": ["process_id"]
	}`)
}

func (t *CampaignStopTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
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
		return errorResult("process_id is required"), nil
	}

	status, err := t.mgr.Status(input.ProcessID)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	if status.Binary != blocktackBinary {
		return errorResult(fmt.Sprintf("process %s is a %s process, not a blocktack campaign", input.ProcessID, status.Binary)), nil
	}

	wasRunning := status.Running
	if err := t.mgr.Stop(input.ProcessID); err != nil {
		return errorResult("failed to stop campaign: " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## BlockTack Campaign Stopped\n\n")
	if wasRunning {
		sb.WriteString("- **Status:** stopped (SIGTERM to the process group; anvil forks killed with it)\n")
	} else {
		sb.WriteString("- **Status:** no-op (the campaign had already exited")
		if status.ExitCode != 0 {
			fmt.Fprintf(&sb, " with code %d", status.ExitCode)
		}
		sb.WriteString(")\n")
	}
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", input.ProcessID)
	sb.WriteString("\n- `blocktack_campaign_results` can still read the run directory's status.json and any completed artifacts.\n")
	return textResult(sb.String()), nil
}
