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
	PoisonTarget string `json:"poison_target,omitempty"`
	Endpoint     string `json:"endpoint,omitempty"`
	Strategy     string `json:"strategy,omitempty"`
}

type ObsPoisonTool struct {
	exec executor.Executor
}

func NewObsPoison(exec executor.Executor) *ObsPoisonTool {
	return &ObsPoisonTool{exec: exec}
}

func (t *ObsPoisonTool) Name() string { return "kubedagger_obs_poison" }

func (t *ObsPoisonTool) Description() string {
	return "Poison observability pipelines (Prometheus, OpenTelemetry, statsd) by tampering with metrics and telemetry in transit. Injects fake data, replays stale metrics, or corrupts payloads to hide attacker activity from dashboards and alerts."
}

func (t *ObsPoisonTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"poison_target": {
				"type": "string",
				"enum": ["prometheus", "otel", "statsd"],
				"description": "Observability system to poison (default: prometheus)"
			},
			"endpoint": {
				"type": "string",
				"description": "Endpoint of the observability system to target"
			},
			"strategy": {
				"type": "string",
				"enum": ["inject", "replay", "corrupt"],
				"description": "Poisoning strategy (default: inject)"
			}
		}
	}`)
}

func (t *ObsPoisonTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ObsPoisonInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Endpoint, "endpoint"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"obs-poison"}
	if input.PoisonTarget != "" {
		args = append(args, "--poison-target", input.PoisonTarget)
	}
	if input.Endpoint != "" {
		args = append(args, "--endpoint", input.Endpoint)
	}
	if input.Strategy != "" {
		args = append(args, "--strategy", input.Strategy)
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
	target := input.PoisonTarget
	if target == "" {
		target = "prometheus"
	}
	fmt.Fprintf(&sb, "## KubeDagger Observability Poisoning: %s\n\n", target)
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
