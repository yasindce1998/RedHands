package firmware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// firmware_extract — binwalk auto-extraction (HIGH IMPACT: writes files)
// ---------------------------------------------------------------------------

// maxExtractedListing caps how many extracted files are listed individually
// in the result; the total count is always reported.
const maxExtractedListing = 100

// FirmwareExtractTool runs `binwalk -e -C <output_dir> [flags] <image>`:
// automatic extraction of known file types from a firmware image, or a
// targeted --dd carve. binwalk v2.3.1 DOES have -C/--directory (verified in
// src/binwalk/modules/extractor.py), so extraction can be directed into an
// explicit output directory: it lands in <output_dir>/_<image
// basename>.extracted/. Recursive extraction (depth > 1) forces binwalk
// verbose mode, which interleaves FILE/MD5SUM/TIMESTAMP rows into the CSV
// log; the CSV parser skips them.
type FirmwareExtractTool struct {
	exec executor.Executor
}

// NewFirmwareExtract constructs the firmware_extract tool.
func NewFirmwareExtract(exec executor.Executor) *FirmwareExtractTool {
	return &FirmwareExtractTool{exec: exec}
}

func (t *FirmwareExtractTool) Name() string { return "firmware_extract" }

func (t *FirmwareExtractTool) Description() string {
	return "Extract embedded file systems, archives and other components from a firmware image with binwalk auto-extraction into an output directory (results land in <output_dir>/_<image>.extracted/), optionally recursing into nested containers, or carve only signatures matching a targeted --dd rule. HIGH IMPACT: writes files to the output directory and runs external extraction utilities (e.g. unsquashfs, sasquatch) on carved data; extraction can also be used to unpack password-protected or malformed archives. Only extract firmware you are authorized to analyze, in an isolated environment, and treat extracted files as untrusted. Approval-gated." + authorizedUseNotice
}

func (t *FirmwareExtractTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the firmware image to extract from (must exist)"
			},
			"output_dir": {
				"type": "string",
				"description": "Base directory for extraction output (required; created with 0700 if missing). binwalk extracts into <output_dir>/_<image basename>.extracted/"
			},
			"depth": {
				"type": "integer",
				"description": "Recursive extraction depth (-d, matryoshka): values > 1 make binwalk recursively scan and re-extract nested containers (1-64)"
			},
			"include": {
				"type": "string",
				"description": "Only extract results whose description matches this filter (-y); simple pattern only, shell metacharacters are rejected"
			},
			"exclude": {
				"type": "string",
				"description": "Skip results whose description matches this filter (-x); simple pattern only, shell metacharacters are rejected"
			},
			"dd": {
				"type": "string",
				"description": "Targeted carve rule <signature>:<extension> (e.g. squashfs:*.sqfs), passed as --dd INSTEAD of full auto-extraction; carves matching signatures without running extraction utilities. The optional binwalk command component (<sig>:<ext>:<cmd>) is not exposed"
			}
		},
		"required": ["image", "output_dir"]
	}`)
}

type firmwareExtractInput struct {
	Image     string `json:"image"`
	OutputDir string `json:"output_dir"`
	Depth     *int64 `json:"depth,omitempty"`
	Include   string `json:"include,omitempty"`
	Exclude   string `json:"exclude,omitempty"`
	DD        string `json:"dd,omitempty"`
}

// extractSummary is the JSON summary combining the parsed CSV signature rows
// with the extraction results on disk.
type extractSummary struct {
	Image               string          `json:"image"`
	OutputDir           string          `json:"output_dir"`
	ExtractionDirectory string          `json:"extraction_directory"`
	SignatureCount      int             `json:"signature_count"`
	Signatures          []signatureRow  `json:"signatures"`
	ExtractedFileCount  int             `json:"extracted_file_count"`
	ExtractedFiles      []extractedFile `json:"extracted_files"`
}

func (t *FirmwareExtractTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareExtractInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateImageFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateOutputDir(input.OutputDir, "output_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt("depth", input.Depth, 1, 64); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Include, "include"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Exclude, "exclude"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateDDRule(input.DD); err != nil {
		return errorResult(err.Error()), nil
	}

	logPath, err := newCSVLog()
	if err != nil {
		return errorResult(err.Error()), nil
	}
	defer removeLog(logPath)

	// -B keeps the signature scan explicit; --csv -f <log> -q captures the
	// structured results (binwalk v2 writes CSV only to the -f log).
	args := []string{"-B", "--csv", "-f", logPath, "-q", "-C", input.OutputDir}
	if input.DD != "" {
		// A --dd rule enables the extractor by itself with only the manual
		// rule; -e would additionally load the default extract.conf rules.
		args = append(args, "-D", input.DD)
	} else {
		args = append(args, "-e")
	}
	if input.Depth != nil {
		args = append(args, "-d", fmt.Sprintf("%d", *input.Depth))
	}
	if input.Include != "" {
		args = append(args, "-y", input.Include)
	}
	if input.Exclude != "" {
		args = append(args, "-x", input.Exclude)
	}
	args = append(args, input.Image)

	stdout, errResult := runBinwalk(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var rows []signatureRow
	if data, ok := readCSVLog(logPath); ok {
		rows = parseBinwalkCSV(data)
	}

	extractionDir := findExtractionDirectory(input.OutputDir, input.Image)
	files, total := listExtractedFiles(input.OutputDir, maxExtractedListing)
	if files == nil {
		files = []extractedFile{}
	}
	summary := extractSummary{
		Image:               input.Image,
		OutputDir:           input.OutputDir,
		ExtractionDirectory: extractionDir,
		SignatureCount:      len(rows),
		Signatures:          rows,
		ExtractedFileCount:  total,
		ExtractedFiles:      files,
	}
	if summary.Signatures == nil {
		summary.Signatures = []signatureRow{}
	}

	var sb strings.Builder
	sb.WriteString("## Firmware Extraction (binwalk) — HIGH IMPACT\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	fmt.Fprintf(&sb, "- **Output directory:** %s\n", input.OutputDir)
	fmt.Fprintf(&sb, "- **Extraction directory:** %s\n", extractionDir)
	if input.DD != "" {
		fmt.Fprintf(&sb, "- **Carve rule (--dd):** %s\n", input.DD)
	} else {
		sb.WriteString("- **Mode:** auto-extraction (-e)\n")
	}
	if input.Depth != nil {
		fmt.Fprintf(&sb, "- **Recursion depth:** %d\n", *input.Depth)
	}
	fmt.Fprintf(&sb, "- **Signatures found:** %d\n", summary.SignatureCount)
	fmt.Fprintf(&sb, "- **Extracted files:** %d", total)
	if total > maxExtractedListing {
		fmt.Fprintf(&sb, " (listing first %d)", maxExtractedListing)
	}
	sb.WriteString("\n\n")

	if total == 0 {
		sb.WriteString("No files were extracted; check the scan results below — the image may contain no signatures with extraction rules.\n\n")
	}

	sb.WriteString("### Extraction summary\n\n```json\n")
	sb.WriteString(marshalSummary(summary))
	sb.WriteString("\n```\n\n")

	if data, ok := readCSVLog(logPath); ok {
		sb.WriteString("### Scan results (CSV)\n\n```csv\n")
		sb.WriteString(strings.TrimSpace(string(data)))
		sb.WriteString("\n```\n\n")
	} else if out := strings.TrimSpace(stdout); out != "" {
		sb.WriteString("### binwalk stdout\n\n```\n")
		sb.WriteString(out)
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString("Extracted firmware contents are untrusted input: inspect them only in an isolated environment authorized for this analysis.\n")

	return textResult(sb.String()), nil
}
