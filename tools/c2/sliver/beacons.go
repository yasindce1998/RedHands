package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type BeaconsInput struct {
	Action   string `json:"action"`
	BeaconID string `json:"beacon_id,omitempty"`
}

type BeaconsTool struct {
	exec executor.Executor
}

func NewBeacons(exec executor.Executor) *BeaconsTool {
	return &BeaconsTool{exec: exec}
}

func (t *BeaconsTool) Name() string { return "sliver_beacons" }

func (t *BeaconsTool) Description() string {
	return "List and interact with Sliver C2 beacons. Beacons check in periodically (jitter-based) for tasking, providing more stealthy communication than sessions."
}

func (t *BeaconsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "use", "kill"],
				"description": "Beacon action"
			},
			"beacon_id": {
				"type": "string",
				"description": "Beacon ID (required for use/kill)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *BeaconsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input BeaconsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.BeaconID, "beacon_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "list":
		args = []string{"beacons"}
	case "use":
		if input.BeaconID == "" {
			return errorResult("beacon_id is required for use action"), nil
		}
		args = []string{"use", "-b", input.BeaconID}
	case "kill":
		if input.BeaconID == "" {
			return errorResult("beacon_id is required for kill action"), nil
		}
		args = []string{"beacons", "--kill", input.BeaconID}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver beacons failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Sliver Beacons: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No active beacons.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
