package whatweb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FingerprintInput struct {
	Target     string `json:"target"`
	Aggression int    `json:"aggression,omitempty"`
	Verbose    bool   `json:"verbose,omitempty"`
}

type FingerprintTool struct {
	exec *executor.BinaryExecutor
}

func NewFingerprint(exec *executor.BinaryExecutor) *FingerprintTool {
	return &FingerprintTool{exec: exec}
}

func (t *FingerprintTool) Name() string { return "whatweb_fingerprint" }

func (t *FingerprintTool) Description() string {
	return "Web technology fingerprinting tool. Identifies CMS, frameworks, JavaScript libraries, web servers, embedded devices, and more."
}

func (t *FingerprintTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target URL or host (e.g., 'https://example.com')"
			},
			"aggression": {
				"type": "integer",
				"description": "Aggression level 1-4 (1=stealthy, 3=aggressive, 4=heavy)"
			},
			"verbose": {
				"type": "boolean",
				"description": "Enable verbose output with detailed plugin results"
			}
		},
		"required": ["target"]
	}`)
}

func (t *FingerprintTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FingerprintInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Target, "--color=never", "--no-errors"}

	if input.Aggression > 0 {
		args = append(args, fmt.Sprintf("-a=%d", input.Aggression))
	}
	if input.Verbose {
		args = append(args, "-v")
	}

	result, err := t.exec.Run(ctx, "whatweb", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("whatweb execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## WhatWeb Fingerprint: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("No results.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > 2048 {
		return fmt.Errorf("target too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(target, c) {
			return fmt.Errorf("target contains forbidden character: %q", c)
		}
	}
	return nil
}
