package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ObsPoisonInput struct {
	Target  string `json:"target"`
	Action  string `json:"action,omitempty"`
	Payload string `json:"payload,omitempty"`
	Filter  string `json:"filter,omitempty"`
}

type ObsPoisonTool struct {
	exec executor.Executor
}

func NewObsPoison(exec executor.Executor) *ObsPoisonTool {
	return &ObsPoisonTool{exec: exec}
}

func (t *ObsPoisonTool) Name() string { return "kubedagger_obs_poison" }

func (t *ObsPoisonTool) Description() string {
	return "Poison observability pipelines (Prometheus, OpenTelemetry, Jaeger) by intercepting and modifying metrics, traces, and logs at the kernel level. Inject false data, suppress alerts, or redirect telemetry to attacker-controlled endpoints."
}

func (t *ObsPoisonTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"enum": ["prometheus", "otel", "jaeger", "fluentd", "datadog"],
				"description": "Observability system to poison"
			},
			"action": {
				"type": "string",
				"enum": ["suppress", "inject", "modify", "redirect"],
				"description": "Poisoning action"
			},
			"payload": {
				"type": "string",
				"description": "Custom payload or metric value to inject"
			},
			"filter": {
				"type": "string",
				"description": "Filter pattern for which events to target"
			}
		},
		"required": ["target"]
	}`)
}

func (t *ObsPoisonTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ObsPoisonInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"obs-poison", "--target", input.Target}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Payload != "" {
		args = append(args, "--payload", input.Payload)
	}
	if input.Filter != "" {
		args = append(args, "--filter", input.Filter)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger obs-poison failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Observability Poisoning: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("Poisoning active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
