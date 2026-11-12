package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// OffenseStopTool stops an offense daemon previously started with
// aegis_offense_start.
type OffenseStopTool struct {
	mgr *executor.BackgroundManager
}

// NewOffenseStop constructs the aegis_offense_stop tool.
func NewOffenseStop(mgr *executor.BackgroundManager) *OffenseStopTool {
	return &OffenseStopTool{mgr: mgr}
}

func (t *OffenseStopTool) Name() string { return "aegis_offense_stop" }

func (t *OffenseStopTool) Description() string {
	return "Stop an Aegis-Shadow offense rootkit loader started with aegis_offense_start (SIGTERM to its process group, SIGKILL after 5 seconds). Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Stopping an unknown process ID is an error; stopping an already-exited daemon is a no-op."
}

func (t *OffenseStopTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by aegis_offense_start (e.g. proc_1a2b3c4d5e6f7a8b)"
			}
		},
		"required": ["process_id"]
	}`)
}

func (t *OffenseStopTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
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
	sb.WriteString("## Aegis-Shadow Offense Rootkit Loader Stopped\n\n")
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", input.ProcessID)
	sb.WriteString("- The daemon's process group received SIGTERM (SIGKILL after 5 seconds if needed).\n")
	fmt.Fprintf(&sb, "- Use `aegis_offense_status` with process_id `%s` to confirm the final state.\n", input.ProcessID)
	sb.WriteString("- Verify eBPF cleanup afterwards with `sudo bpftool prog show` and `ls /sys/fs/bpf`.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
