package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ScanInput struct {
	Target    string `json:"target"`
	Baseline  string `json:"baseline,omitempty"`
	Report    bool   `json:"report,omitempty"`
	Format    string `json:"format,omitempty"`
	Output    string `json:"output,omitempty"`
	ScanTypes string `json:"scan_types,omitempty"`
}

type ScanTool struct {
	exec executor.Executor
}

func NewScan(exec executor.Executor) *ScanTool {
	return &ScanTool{exec: exec}
}

func (t *ScanTool) Name() string { return "barzakh_scan" }

func (t *ScanTool) Description() string {
	return "Scan a UEFI firmware image for bootkit indicators using 43 specialized detectors. Detects trampoline hooks, SPI flash modifications, SMM backdoors, ACPI implants, Secure Boot bypasses, and more. Scans complete in under 500ms per image."
}

func (t *ScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the UEFI firmware image to scan"
			},
			"baseline": {
				"type": "string",
				"description": "Path to a known-good baseline JSON for comparison"
			},
			"report": {
				"type": "boolean",
				"description": "Generate a detection report (default: false)"
			},
			"format": {
				"type": "string",
				"enum": ["html", "json"],
				"description": "Report output format (requires --report)"
			},
			"output": {
				"type": "string",
				"description": "Output file path for the report"
			},
			"scan_types": {
				"type": "string",
				"description": "Comma-separated detector categories to run (e.g. spi,smm,acpi,me,hook)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *ScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Target == "" {
		return errorResult("target firmware path is required"), nil
	}
	if err := validatePath(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Baseline, "baseline"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ScanTypes, "scan_types"); err != nil {
		return errorResult(err.Error()), nil
	}

	validFormats := map[string]bool{"html": true, "json": true}
	if input.Format != "" && !validFormats[input.Format] {
		return errorResult("invalid format: must be html or json"), nil
	}

	args := []string{"--target", input.Target}
	if input.Baseline != "" {
		args = append(args, "--baseline", input.Baseline)
	}
	if input.Report {
		args = append(args, "--report")
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}
	if input.ScanTypes != "" {
		args = append(args, "--scan-types", input.ScanTypes)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## UEFI Firmware Scan Results\n\n")
	fmt.Fprintf(&sb, "- **Target:** %s\n", input.Target)
	if input.Baseline != "" {
		fmt.Fprintf(&sb, "- **Baseline:** %s\n", input.Baseline)
	}
	if input.ScanTypes != "" {
		fmt.Fprintf(&sb, "- **Scan types:** %s\n", input.ScanTypes)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Scan completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
