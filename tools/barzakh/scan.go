package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Exit code 1 from `barzakh-scanner scan` means "bootkit detected" and from
// `barzakh-adversary scenario run` means "chain not fully detected". Both are
// valid command results with output on stdout, not execution failures.
// Exit code 2 from barzakh-scanner means "scan incomplete" and stays an error.
const exitCodeDetection = 1

// scanFormats mirrors the --format values accepted by `barzakh-scanner scan`.
var scanFormats = []string{"json", "html", "markdown", "sarif", "csv", "ecs", "cef", "leef"}

type ScanInput struct {
	Target    string `json:"target"`
	Baseline  string `json:"baseline,omitempty"`
	Report    string `json:"report,omitempty"`
	Format    string `json:"format,omitempty"`
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
	return "Scan a UEFI firmware image for bootkit indicators using 138 specialized detectors. Detects trampoline hooks, SPI flash modifications, SMM backdoors, ACPI implants, Secure Boot bypasses, and more. Findings are emitted as structured JSON and summarized by severity. A bootkit detection (scanner exit code 1) is reported as a detection result, not a tool error; exit code 2 (scan incomplete) is reported as an error."
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
				"type": "string",
				"description": "Write a full scan report to this file path (passed as --report <PATH>; barzakh-scanner has no --output flag)"
			},
			"format": {
				"type": "string",
				"enum": ["json", "html", "markdown", "sarif", "csv", "ecs", "cef", "leef"],
				"description": "Format for the report file written via report"
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
	if err := validatePath(input.Report, "report"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.ScanTypes, "scan_types"); err != nil {
		return errorResult(err.Error()), nil
	}

	validFormats := make(map[string]bool, len(scanFormats))
	for _, f := range scanFormats {
		validFormats[f] = true
	}
	if input.Format != "" && !validFormats[input.Format] {
		return errorResult("invalid format: must be one of " + strings.Join(scanFormats, ", ")), nil
	}

	// barzakh-scanner exposes scanning as the `scan` subcommand. --json makes
	// the scanner emit structured findings JSON on stdout, which is summarized
	// (and passed through raw) below.
	args := []string{"scan", "--target", input.Target, "--json"}
	if input.Baseline != "" {
		args = append(args, "--baseline", input.Baseline)
	}
	if input.Report != "" {
		// --report takes a value (the report file path); it is not a boolean flag.
		args = append(args, "--report", input.Report)
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}
	if input.ScanTypes != "" {
		args = append(args, "--scan-types", input.ScanTypes)
	}

	result, detected, err := runWithDetectionExit(ctx, t.exec, exitCodeDetection, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner scan failed (exit code 2 means scan incomplete): %s\n%s", err.Error(), stderr)), nil
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
	if input.Report != "" {
		fmt.Fprintf(&sb, "- **Report file:** %s\n", input.Report)
	}
	if detected {
		sb.WriteString("- **Result:** ⚠️ BOOTKIT DETECTED (scanner exit code 1)\n")
	} else {
		sb.WriteString("- **Result:** no bootkit indicators detected\n")
	}
	sb.WriteString("\n")

	summary, isJSON := summarizeFindings(output)
	if summary != "" {
		sb.WriteString(summary)
	}

	switch {
	case output != "" && isJSON:
		sb.WriteString("```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	case output != "":
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	case detected:
		sb.WriteString("Scanner reported a detection via exit code 1 but produced no JSON output.\n")
	default:
		sb.WriteString("Scan completed with no findings output.\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// runWithDetectionExit executes binary and treats detectionExit as a
// successful "detection" outcome rather than an error. This is needed because
// the executor turns every non-zero process exit into an error, while
// barzakh-scanner (exit 1 = bootkit detected) and barzakh-adversary scenario
// run (exit 1 = chain not fully detected) use exit code 1 for valid results.
//
// The executor returns a non-nil *Result carrying ExitCode and the captured
// stdout/stderr alongside the error, so the exit code can be inspected
// directly. Cancellations, timeouts, and output truncation are reported with
// different error messages (and typically a signal-killed exit code of -1),
// so we additionally match the executor's "execution failed (exit N)" error
// text to make sure a genuine process exit produced the error.
func runWithDetectionExit(ctx context.Context, exec executor.Executor, detectionExit int, binary string, args ...string) (*executor.Result, bool, error) {
	result, err := exec.Run(ctx, binary, args...)
	if err == nil {
		return result, false, nil
	}
	if result != nil && result.ExitCode == detectionExit && isProcessExitError(err, detectionExit) {
		return result, true, nil
	}
	return result, false, err
}

// isProcessExitError reports whether err is the executor's error for a normal
// process exit with the given code, as opposed to a timeout, cancellation, or
// truncated-output error.
func isProcessExitError(err error, code int) bool {
	return err != nil && strings.Contains(err.Error(), fmt.Sprintf("execution failed (exit %d)", code))
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// summarizeFindings extracts a per-severity finding count from the scanner's
// --json stdout when it parses cleanly as findings JSON. It returns
// ok=false when the output is not recognizable findings JSON, in which case
// the raw output should be passed through unchanged.
//
// The real `barzakh-scanner scan --target X --json` stdout is a top-level
// JSON array of finding objects (verified against barzakh-scanner 0.7.0
// output, see testdata/barzakh/). An enveloped {"findings": [...]} object is
// also accepted for compatibility.
func summarizeFindings(output string) (string, bool) {
	if output == "" {
		return "", false
	}
	var findings []struct {
		Severity string `json:"severity"`
	}
	var doc struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(output), &doc); err == nil && len(doc.Findings) > 0 {
		findings = doc.Findings
	} else if err := json.Unmarshal([]byte(output), &findings); err != nil || len(findings) == 0 {
		return "", false
	}

	counts := make(map[string]int)
	for _, f := range findings {
		severity := f.Severity
		if severity == "" {
			severity = "unknown"
		}
		counts[severity]++
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "- **Findings:** %d\n", len(findings))
	for _, severity := range severityOrder {
		if counts[severity] > 0 {
			fmt.Fprintf(&sb, "  - %s: %d\n", severity, counts[severity])
			delete(counts, severity)
		}
	}
	rest := make([]string, 0, len(counts))
	for severity := range counts {
		rest = append(rest, severity)
	}
	sort.Strings(rest)
	for _, severity := range rest {
		fmt.Fprintf(&sb, "  - %s: %d\n", severity, counts[severity])
	}
	return sb.String(), true
}
