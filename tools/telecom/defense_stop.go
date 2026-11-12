package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// DefenseStopTool stops a defense daemon previously started with
// telecom_defense_start.
type DefenseStopTool struct {
	mgr *executor.BackgroundManager
}

// NewDefenseStop constructs the telecom_defense_stop tool.
func NewDefenseStop(mgr *executor.BackgroundManager) *DefenseStopTool {
	return &DefenseStopTool{mgr: mgr}
}

func (t *DefenseStopTool) Name() string { return "telecom_defense_stop" }

func (t *DefenseStopTool) Description() string {
	return "Stop a StaticZero defense daemon started with telecom_defense_start (SIGTERM to its process group, SIGKILL after 5 seconds). Wraps StaticZero (eBPF telecom security research); authorized lab use only. Stopping an unknown process ID is an error; stopping an already-exited daemon is a no-op."
}

func (t *DefenseStopTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by telecom_defense_start (e.g. proc_1a2b3c4d5e6f7a8b)"
			}
		},
		"required": ["process_id"]
	}`)
}

func (t *DefenseStopTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if input.ProcessID == "" {
		return errorResult("process_id is required"), nil
	}
	if err := validateSafeString(input.ProcessID, "process_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := t.mgr.Stop(input.ProcessID); err != nil {
		return errorResult(err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## StaticZero Defense Daemon Stopped\n\n")
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", input.ProcessID)
	sb.WriteString("- The daemon's process group received SIGTERM (SIGKILL after 5 seconds if needed).\n")
	fmt.Fprintf(&sb, "- Use `telecom_defense_status` with process_id `%s` to confirm the final state.\n", input.ProcessID)

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
