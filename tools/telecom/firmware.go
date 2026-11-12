package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// runModemFirmware executes modem-firmware and returns stdout plus an error
// result on failure (shared by all firmware tools).
func runModemFirmware(ctx context.Context, exec executor.Executor, args []string) (string, *mcp.ToolResult) {
	result, err := exec.Run(ctx, "modem-firmware", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return "", errorResult(fmt.Sprintf("modem-firmware failed: %s\n%s", err.Error(), stderr))
	}
	stdout := ""
	if result != nil {
		stdout = string(result.Stdout)
	}
	return stdout, nil
}

// ---------------------------------------------------------------------------
// telecom_firmware_analyze — modem-firmware analyze (read-only static analysis)
// ---------------------------------------------------------------------------

// FirmwareAnalyzeTool runs `modem-firmware analyze`: static pattern analysis
// of a modem firmware image producing a VulnerabilityReport JSON.
type FirmwareAnalyzeTool struct {
	exec executor.Executor
}

func NewFirmwareAnalyze(exec executor.Executor) *FirmwareAnalyzeTool {
	return &FirmwareAnalyzeTool{exec: exec}
}

func (t *FirmwareAnalyzeTool) Name() string { return "telecom_firmware_analyze" }

func (t *FirmwareAnalyzeTool) Description() string {
	return "Run read-only static vulnerability analysis on a modem/baseband firmware image (modem-firmware analyze): detects dangerous function usage, weak ciphers, debug interfaces, hardcoded credentials, attack surfaces, and protocol handlers; writes a JSON findings report. Read-only with respect to the target system." + authorizedUseNotice
}

func (t *FirmwareAnalyzeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the firmware image to analyze (must exist)"
			},
			"chipset": {
				"type": "string",
				"enum": ["qualcomm", "mediatek", "samsung-shannon", "intel-xgold", "huawei-balong"],
				"description": "Modem chipset family (the aliases shannon, intel, and balong are also accepted)"
			},
			"report": {
				"type": "string",
				"description": "Output path for the JSON vulnerability report (defaults to ./fw_analysis.json; contents are included in the tool result when written)"
			}
		},
		"required": ["target", "chipset"]
	}`)
}

type firmwareAnalyzeInput struct {
	Target  string `json:"target"`
	Chipset string `json:"chipset"`
	Report  string `json:"report,omitempty"`
}

func (t *FirmwareAnalyzeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareAnalyzeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInputFile(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateChipset(input.Chipset); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Report, "report"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"analyze", "--target", input.Target, "--chipset", input.Chipset}
	if input.Report != "" {
		args = append(args, "--report", input.Report)
	}

	stdout, errResult := runModemFirmware(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var sb strings.Builder
	sb.WriteString("## Modem Firmware Analysis\n\n")
	fmt.Fprintf(&sb, "- **Target:** %s\n", input.Target)
	fmt.Fprintf(&sb, "- **Chipset:** %s\n", input.Chipset)
	if input.Report != "" {
		fmt.Fprintf(&sb, "- **Report file:** %s\n", input.Report)
	}
	sb.WriteString("\n")
	if report, ok := readArtifactIfPresent(input.Report); ok {
		sb.WriteString("### Vulnerability report\n\n```json\n")
		sb.WriteString(strings.TrimSpace(report))
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("No report file was readable; analyzer log output below.\n\n```\n")
		sb.WriteString(strings.TrimSpace(stdout))
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// telecom_firmware_extract — modem-firmware extract
// ---------------------------------------------------------------------------

// FirmwareExtractTool runs `modem-firmware extract`: splits a modem image
// into per-section binaries plus a manifest.json in the output directory.
type FirmwareExtractTool struct {
	exec executor.Executor
}

func NewFirmwareExtract(exec executor.Executor) *FirmwareExtractTool {
	return &FirmwareExtractTool{exec: exec}
}

func (t *FirmwareExtractTool) Name() string { return "telecom_firmware_extract" }

func (t *FirmwareExtractTool) Description() string {
	return "Extract firmware components (boot ROM, modem code, DSP, certificates) from a modem/baseband image into an output directory with a manifest.json (modem-firmware extract)." + authorizedUseNotice
}

func (t *FirmwareExtractTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the firmware image (.mbn, .elf, .bin; must exist)"
			},
			"output": {
				"type": "string",
				"description": "Output directory for extracted components (defaults to ./fw_extracted)"
			},
			"chipset": {
				"type": "string",
				"enum": ["qualcomm", "mediatek", "samsung-shannon", "intel-xgold", "huawei-balong"],
				"description": "Modem chipset family (the aliases shannon, intel, and balong are also accepted)"
			}
		},
		"required": ["image", "chipset"]
	}`)
}

type firmwareExtractInput struct {
	Image   string `json:"image"`
	Output  string `json:"output,omitempty"`
	Chipset string `json:"chipset"`
}

func (t *FirmwareExtractTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareExtractInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInputFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateChipset(input.Chipset); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"extract", "--image", input.Image, "--chipset", input.Chipset}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}

	stdout, errResult := runModemFirmware(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var sb strings.Builder
	sb.WriteString("## Modem Firmware Extraction\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	fmt.Fprintf(&sb, "- **Chipset:** %s\n", input.Chipset)
	if input.Output != "" {
		fmt.Fprintf(&sb, "- **Output directory:** %s\n", input.Output)
	}
	sb.WriteString("\n")
	if manifest, ok := readArtifactIfPresent(filepath.Join(input.Output, "manifest.json")); ok {
		sb.WriteString("### Extraction manifest\n\n```json\n")
		sb.WriteString(strings.TrimSpace(manifest))
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("Extraction log output:\n\n```\n")
		sb.WriteString(strings.TrimSpace(stdout))
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// telecom_firmware_diff — modem-firmware diff
// ---------------------------------------------------------------------------

// FirmwareDiffTool runs `modem-firmware diff`: compares two firmware images
// and reports differing byte regions.
type FirmwareDiffTool struct {
	exec executor.Executor
}

func NewFirmwareDiff(exec executor.Executor) *FirmwareDiffTool {
	return &FirmwareDiffTool{exec: exec}
}

func (t *FirmwareDiffTool) Name() string { return "telecom_firmware_diff" }

func (t *FirmwareDiffTool) Description() string {
	return "Diff two modem firmware images and report differing byte regions, size changes, and section layout differences (modem-firmware diff). Read-only comparison of the two inputs." + authorizedUseNotice
}

func (t *FirmwareDiffTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"old": {
				"type": "string",
				"description": "Path to the first (old/baseline) firmware image (must exist)"
			},
			"new": {
				"type": "string",
				"description": "Path to the second (new) firmware image (must exist)"
			},
			"chipset": {
				"type": "string",
				"enum": ["qualcomm", "mediatek", "samsung-shannon", "intel-xgold", "huawei-balong"],
				"description": "Modem chipset family (the aliases shannon, intel, and balong are also accepted)"
			}
		},
		"required": ["old", "new", "chipset"]
	}`)
}

type firmwareDiffInput struct {
	Old     string `json:"old"`
	New     string `json:"new"`
	Chipset string `json:"chipset"`
}

func (t *FirmwareDiffTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareDiffInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInputFile(input.Old, "old"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateInputFile(input.New, "new"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateChipset(input.Chipset); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"diff", "--old", input.Old, "--new", input.New, "--chipset", input.Chipset}

	stdout, errResult := runModemFirmware(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var sb strings.Builder
	sb.WriteString("## Modem Firmware Diff\n\n")
	fmt.Fprintf(&sb, "- **Old:** %s\n", input.Old)
	fmt.Fprintf(&sb, "- **New:** %s\n", input.New)
	fmt.Fprintf(&sb, "- **Chipset:** %s\n", input.Chipset)
	sb.WriteString("\n```\n")
	diffOut := strings.TrimSpace(stdout)
	if diffOut == "" {
		diffOut = "Diff completed (no output)."
	}
	sb.WriteString(diffOut)
	sb.WriteString("\n```\n")

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// telecom_firmware_nv_dump — modem-firmware nv-dump
// ---------------------------------------------------------------------------

// FirmwareNvDumpTool runs `modem-firmware nv-dump`: extracts NV items
// (carrier config, band settings, security-relevant items) to JSON.
type FirmwareNvDumpTool struct {
	exec executor.Executor
}

func NewFirmwareNvDump(exec executor.Executor) *FirmwareNvDumpTool {
	return &FirmwareNvDumpTool{exec: exec}
}

func (t *FirmwareNvDumpTool) Name() string { return "telecom_firmware_nv_dump" }

func (t *FirmwareNvDumpTool) Description() string {
	return "Extract NV items (carrier configuration, band settings, security-relevant lock codes and roaming lists) from an NV image or EFS dump into a JSON report (modem-firmware nv-dump)." + authorizedUseNotice
}

func (t *FirmwareNvDumpTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the NV image or EFS dump (must exist)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the NV items JSON (defaults to ./nv_items.json; contents are included in the tool result when written)"
			}
		},
		"required": ["image"]
	}`)
}

type firmwareNvDumpInput struct {
	Image  string `json:"image"`
	Output string `json:"output,omitempty"`
}

func (t *FirmwareNvDumpTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareNvDumpInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInputFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"nv-dump", "--image", input.Image}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}

	stdout, errResult := runModemFirmware(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var sb strings.Builder
	sb.WriteString("## Modem NV Item Dump\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	if input.Output != "" {
		fmt.Fprintf(&sb, "- **Output file:** %s\n", input.Output)
	}
	sb.WriteString("\n")
	if items, ok := readArtifactIfPresent(input.Output); ok {
		sb.WriteString("### NV items\n\n```json\n")
		sb.WriteString(strings.TrimSpace(items))
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("No output file was readable; tool log output below.\n\n```\n")
		sb.WriteString(strings.TrimSpace(stdout))
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
