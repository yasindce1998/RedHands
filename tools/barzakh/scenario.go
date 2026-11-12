package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var scenarioActions = []string{"list", "show", "run"}

type ScenarioInput struct {
	Action string `json:"action"`
	Name   string `json:"name,omitempty"`
	Output string `json:"output,omitempty"`
	JSON   bool   `json:"json,omitempty"`
}

type ScenarioTool struct {
	exec executor.Executor
}

func NewScenario(exec executor.Executor) *ScenarioTool {
	return &ScenarioTool{exec: exec}
}

func (t *ScenarioTool) Name() string { return "barzakh_scenario" }

func (t *ScenarioTool) Description() string {
	return "List, inspect, or run bundled multi-stage bootkit scenario chains that exercise full attack paths across payloads. Six chains are bundled: blacklotus-chain, dma-preboot-chain, mobile-bootchain, nvram-downgrade-chain, rustkit-ffi-chain, and smm-persistence-chain. For run, a chain that is not fully detected (adversary exit code 1) is reported as a result, not an error."
}

func (t *ScenarioTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["list", "show", "run"],
				"description": "list chains, show chain details, or run a chain"
			},
			"name": {
				"type": "string",
				"description": "Scenario chain name (required for show and run), e.g. blacklotus-chain"
			},
			"output": {
				"type": "string",
				"description": "Output path for run artifacts"
			},
			"json": {
				"type": "boolean",
				"description": "Emit structured JSON results (run only)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ScenarioTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ScenarioInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	validActions := make(map[string]bool, len(scenarioActions))
	for _, a := range scenarioActions {
		validActions[a] = true
	}
	if !validActions[input.Action] {
		return errorResult("invalid action: must be one of " + strings.Join(scenarioActions, ", ")), nil
	}
	if (input.Action == "show" || input.Action == "run") && input.Name == "" {
		return errorResult("name is required for show and run"), nil
	}
	if err := validateName(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"scenario", input.Action}
	if input.Action != "list" {
		args = append(args, "--name", input.Name)
	}
	if input.Action == "run" {
		if input.Output != "" {
			args = append(args, "--output", input.Output)
		}
		if input.JSON {
			args = append(args, "--json")
		}
	}

	// `scenario run` exits 1 when the chain is not fully detected by the
	// scanner — a valid outcome with JSON results on stdout, not a failure.
	result, notDetected, err := runWithDetectionExit(ctx, t.exec, exitCodeDetection, "barzakh-adversary", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-adversary scenario %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Barzakh Scenario\n\n")
	fmt.Fprintf(&sb, "- **Action:** %s\n", input.Action)
	if input.Name != "" {
		fmt.Fprintf(&sb, "- **Chain:** %s\n", input.Name)
	}
	if input.Action == "run" && input.Output != "" {
		fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
	}
	if input.Action == "run" {
		if notDetected {
			sb.WriteString("- **Result:** ⚠️ chain NOT fully detected (detection coverage gap; adversary exit code 1)\n")
		} else {
			sb.WriteString("- **Result:** chain fully detected\n")
		}
	}
	sb.WriteString("\n")

	if output == "" {
		sb.WriteString("Scenario completed (no output).\n")
	} else if input.Action == "run" && input.JSON {
		sb.WriteString("```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
