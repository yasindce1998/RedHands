package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// reportFormats mirrors the --format values accepted by
// `barzakh-scanner report`. cmd_report parses the value with the same
// barzakh_core::ReportFormat::from_str as `scan`, so the enum is identical
// to scanFormats (json, html, markdown, sarif, csv, ecs, cef, leef).
var reportFormats = scanFormats

// ReportTool wraps `barzakh-scanner report` (verified against scanner
// main.rs):
//
//	report --target <firmware> [--baseline <json>] [--output <path>] [--format <fmt>]
//
// cmd_report scans the target image and writes a report file (default
// report.json, default format json). Unlike `scan`, it does not exit with a
// detection code — the scanner main() exits 2 on error only, so no
// detection-exit handling applies. Because every invocation writes the
// report file, this tool is not read-only.
type ReportInput struct {
	Target   string `json:"target"`
	Baseline string `json:"baseline,omitempty"`
	Output   string `json:"output,omitempty"`
	Format   string `json:"format,omitempty"`
}

type ReportTool struct {
	exec executor.Executor
}

func NewReport(exec executor.Executor) *ReportTool {
	return &ReportTool{exec: exec}
}

func (t *ReportTool) Name() string { return "barzakh_report" }

func (t *ReportTool) Description() string {
	return "Generate a scan report file for a UEFI firmware image (barzakh-scanner report): scans the target with the full detector set and writes the report to the output path in the chosen format (json, html, markdown, sarif, csv, ecs, cef, leef; default json). Optionally compares against a known-good baseline. Writes the report file to output (default report.json) — this tool is not read-only."
}

func (t *ReportTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the UEFI firmware image to scan and report on"
			},
			"baseline": {
				"type": "string",
				"description": "Path to a known-good baseline JSON for comparison"
			},
			"output": {
				"type": "string",
				"description": "Output path for the report file (default: report.json)"
			},
			"format": {
				"type": "string",
				"enum": ["json", "html", "markdown", "sarif", "csv", "ecs", "cef", "leef"],
				"description": "Report file format (default: json)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *ReportTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ReportInput
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

	validFormats := make(map[string]bool, len(reportFormats))
	for _, f := range reportFormats {
		validFormats[f] = true
	}
	if input.Format != "" && !validFormats[input.Format] {
		return errorResult("invalid format: must be one of " + strings.Join(reportFormats, ", ")), nil
	}

	args := []string{"report", "--target", input.Target}
	if input.Baseline != "" {
		args = append(args, "--baseline", input.Baseline)
	}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner report failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Scan Report Generated\n\n")
	fmt.Fprintf(&sb, "- **Target:** %s\n", input.Target)
	if input.Baseline != "" {
		fmt.Fprintf(&sb, "- **Baseline:** %s\n", input.Baseline)
	}
	if input.Output != "" {
		fmt.Fprintf(&sb, "- **Report file:** %s\n", input.Output)
	} else {
		sb.WriteString("- **Report file:** report.json (CLI default)\n")
	}
	if input.Format != "" {
		fmt.Fprintf(&sb, "- **Format:** %s\n", input.Format)
	} else {
		sb.WriteString("- **Format:** json (CLI default)\n")
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Report generation completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
