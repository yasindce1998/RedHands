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
// firmware_scan — binwalk signature scan (read-only)
// ---------------------------------------------------------------------------

// FirmwareScanTool runs `binwalk -B [flags] <image>`: the signature scan for
// embedded file systems, compressed archives, bootloaders, certificates and
// other data inside a firmware image. With the default csv=true the wrapper
// runs `binwalk --csv -f <tmplog> -q` (binwalk v2 only writes CSV to the -f
// log file, never to stdout) and builds a JSON summary by parsing the CSV so
// campaign record rules can map results (e.g. "signatures.0.description").
type FirmwareScanTool struct {
	exec executor.Executor
}

// NewFirmwareScan constructs the firmware_scan tool.
func NewFirmwareScan(exec executor.Executor) *FirmwareScanTool {
	return &FirmwareScanTool{exec: exec}
}

func (t *FirmwareScanTool) Name() string { return "firmware_scan" }

func (t *FirmwareScanTool) Description() string {
	return "Scan a firmware image for embedded file signatures with binwalk: file systems, compressed archives, kernels, bootloaders, certificates and other embedded data, with optional executable-opcode (-A) and entropy (-E) analysis. Returns binwalk's signature table plus a machine-readable JSON summary built from the CSV log (record rules can map signatures.N.offset / signatures.N.description). Read-only with respect to the host system." + authorizedUseNotice
}

func (t *FirmwareScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the firmware image to scan (must exist)"
			},
			"entropy": {
				"type": "boolean",
				"description": "Also run entropy analysis (-E). Note: binwalk suppresses entropy result rows whenever the signature scan reports results, so this mainly helps when few/no signatures are found; use firmware_entropy for dedicated entropy analysis",
				"default": false
			},
			"opcodes": {
				"type": "boolean",
				"description": "Also scan for executable opcode signatures (-A), additive to the normal file signatures",
				"default": false
			},
			"include": {
				"type": "string",
				"description": "Only report results whose description matches this filter (-y); simple pattern only, shell metacharacters are rejected"
			},
			"exclude": {
				"type": "string",
				"description": "Exclude results whose description matches this filter (-x); simple pattern only, shell metacharacters are rejected"
			},
			"csv": {
				"type": "boolean",
				"description": "Request structured CSV output and build the JSON signature summary from it (default true); false returns binwalk's plain text table from stdout",
				"default": true
			}
		},
		"required": ["image"]
	}`)
}

type firmwareScanInput struct {
	Image   string `json:"image"`
	Entropy bool   `json:"entropy,omitempty"`
	Opcodes bool   `json:"opcodes,omitempty"`
	Include string `json:"include,omitempty"`
	Exclude string `json:"exclude,omitempty"`
	CSV     *bool  `json:"csv,omitempty"`
}

// scanSummary is the JSON summary built from the binwalk CSV log. Signatures
// is always an array (never null) so record-rule paths stay valid on
// zero-signature scans.
type scanSummary struct {
	Image          string         `json:"image"`
	SignatureCount int            `json:"signature_count"`
	Signatures     []signatureRow `json:"signatures"`
}

func (t *FirmwareScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateImageFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Include, "include"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Exclude, "exclude"); err != nil {
		return errorResult(err.Error()), nil
	}

	csvOutput := true
	if input.CSV != nil {
		csvOutput = *input.CSV
	}

	// -B is passed explicitly so the signature module runs deterministically
	// alongside -A/-E (binwalk only implies the signature scan when no other
	// module flag was given, and -A alone replaces the magic files).
	args := []string{"-B"}
	logPath := ""
	if csvOutput {
		var err error
		logPath, err = newCSVLog()
		if err != nil {
			return errorResult(err.Error()), nil
		}
		defer removeLog(logPath)
		args = append(args, "--csv", "-f", logPath, "-q")
	}
	if input.Opcodes {
		args = append(args, "-A")
	}
	if input.Entropy {
		// -N (nplot) is mandatory: the entropy module would otherwise call
		// matplotlib plt.show() and hang a headless invocation.
		args = append(args, "-E", "-N")
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

	var sb strings.Builder
	sb.WriteString("## Firmware Signature Scan (binwalk)\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	modules := []string{"signature"}
	if input.Opcodes {
		modules = append(modules, "opcodes")
	}
	if input.Entropy {
		modules = append(modules, "entropy")
	}
	fmt.Fprintf(&sb, "- **Modules:** %s\n", strings.Join(modules, ", "))
	if input.Include != "" {
		fmt.Fprintf(&sb, "- **Include filter:** %s\n", input.Include)
	}
	if input.Exclude != "" {
		fmt.Fprintf(&sb, "- **Exclude filter:** %s\n", input.Exclude)
	}
	sb.WriteString("\n")

	if csvOutput {
		data, ok := readCSVLog(logPath)
		if !ok {
			sb.WriteString("binwalk produced no CSV log; stdout was:\n\n```\n")
			sb.WriteString(strings.TrimSpace(stdout))
			sb.WriteString("\n```\n")
			return textResult(sb.String()), nil
		}

		rows := parseBinwalkCSV(data)
		summary := scanSummary{
			Image:          input.Image,
			SignatureCount: len(rows),
			Signatures:     rows,
		}
		if summary.Signatures == nil {
			summary.Signatures = []signatureRow{}
		}
		fmt.Fprintf(&sb, "- **Signatures found:** %d\n\n", summary.SignatureCount)
		sb.WriteString("### Signature summary\n\n```json\n")
		sb.WriteString(marshalSummary(summary))
		sb.WriteString("\n```\n\n")
		sb.WriteString("### Raw CSV log\n\n```csv\n")
		sb.WriteString(strings.TrimSpace(string(data)))
		sb.WriteString("\n```\n")
	} else {
		sb.WriteString("### binwalk output\n\n```\n")
		out := strings.TrimSpace(stdout)
		if out == "" {
			out = "Scan completed with no output."
		}
		sb.WriteString(out)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
