package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// fuzzProtocols mirrors the protocol names accepted by
// `barzakh-scanner fuzz --protocol` (Protocol::parse in barzakh-core).
var fuzzProtocols = []string{"dhcpv6", "bmp", "capsule", "httpboot", "tcg", "hii"}

// FuzzTool wraps `barzakh-scanner fuzz` (verified against scanner main.rs):
//
//	fuzz [--iterations <n>] [--output-dir <dir>] [--mutate] [--json]
//	     [--protocol dhcpv6|bmp|capsule|httpboot|tcg|hii]
//
// Without --protocol it runs the payload fuzzing harness (writing a corpus
// to --output-dir); with --protocol it runs protocol-aware fuzzing that
// mutates structurally-valid boot-time protocol seeds and measures which
// detectors fire per mutation. fuzz has no detection-exit semantics: the
// scanner main() exits 2 on error, 0 otherwise.
type FuzzInput struct {
	Iterations string `json:"iterations,omitempty"`
	OutputDir  string `json:"output_dir,omitempty"`
	Mutate     bool   `json:"mutate,omitempty"`
	JSON       bool   `json:"json,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type FuzzTool struct {
	exec executor.Executor
}

func NewFuzz(exec executor.Executor) *FuzzTool {
	return &FuzzTool{exec: exec}
}

func (t *FuzzTool) Name() string { return "barzakh_fuzz" }

func (t *FuzzTool) Description() string {
	return "Run the barzakh-scanner fuzzing harness: either payload fuzzing (mutate adversary payloads, write the generated corpus to an output directory, and report detection gaps and undetected categories) or protocol-aware fuzzing of boot-time protocols (dhcpv6, bmp, capsule, httpboot, tcg, hii) that measures which detectors fire per mutated input. Use it to find detection coverage gaps before a red-team engagement."
}

func (t *FuzzTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"iterations": {
				"type": "string",
				"description": "Number of mutation iterations (default: 1)"
			},
			"output_dir": {
				"type": "string",
				"description": "Output directory for the generated fuzz corpus (default: ./fuzz_corpus)"
			},
			"mutate": {
				"type": "boolean",
				"description": "Enable payload mutation (payload harness only)"
			},
			"json": {
				"type": "boolean",
				"description": "Emit results as JSON"
			},
			"protocol": {
				"type": "string",
				"enum": ["dhcpv6", "bmp", "capsule", "httpboot", "tcg", "hii"],
				"description": "Protocol-aware fuzzing target; omit for the payload fuzzing harness"
			}
		},
		"required": []
	}`)
}

func (t *FuzzTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FuzzInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePositiveInt(input.Iterations, "iterations"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.OutputDir, "output_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Protocol != "" && !isValidAction(fuzzProtocols, input.Protocol) {
		return errorResult("invalid protocol: must be one of " + strings.Join(fuzzProtocols, ", ")), nil
	}

	args := []string{"fuzz"}
	if input.Iterations != "" {
		args = append(args, "--iterations", input.Iterations)
	}
	if input.OutputDir != "" {
		args = append(args, "--output-dir", input.OutputDir)
	}
	if input.Mutate {
		args = append(args, "--mutate")
	}
	if input.JSON {
		args = append(args, "--json")
	}
	if input.Protocol != "" {
		args = append(args, "--protocol", input.Protocol)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner fuzz failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Fuzzing Results\n\n")
	if input.Iterations != "" {
		fmt.Fprintf(&sb, "- **Iterations:** %s\n", input.Iterations)
	}
	if input.Protocol != "" {
		fmt.Fprintf(&sb, "- **Protocol:** %s\n", input.Protocol)
	} else if input.OutputDir != "" {
		fmt.Fprintf(&sb, "- **Output dir:** %s\n", input.OutputDir)
	}
	if input.Mutate {
		sb.WriteString("- **Mutate:** enabled\n")
	}
	sb.WriteString("\n")

	if output == "" {
		sb.WriteString("Fuzzing completed (no output).\n")
	} else if input.JSON {
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
