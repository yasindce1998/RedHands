package firmware

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// firmware_entropy — binwalk entropy analysis (read-only)
// ---------------------------------------------------------------------------

// entropyEdgeRegex matches the entropy module's displayed result rows. In
// non-verbose mode (how this wrapper always runs it) only rising/falling
// edge rows have display=True; plain per-block floats are suppressed.
var entropyEdgeRegex = regexp.MustCompile(`^(Rising|Falling) entropy edge \(([0-9]*\.?[0-9]+)\)$`)

// FirmwareEntropyTool runs `binwalk -E -N [-K block] <image>`: entropy
// analysis of a firmware image. binwalk reports rising edges (entropy >= 0.95,
// compressed or encrypted data) and falling edges (entropy <= 0.85, structured
// data such as code or filesystem metadata). The wrapper always passes -N
// (nplot): the entropy module would otherwise call matplotlib plt.show() and
// hang a headless invocation. Structured output uses the --csv -f <log> -q
// route like the other tools.
type FirmwareEntropyTool struct {
	exec executor.Executor
}

// NewFirmwareEntropy constructs the firmware_entropy tool.
func NewFirmwareEntropy(exec executor.Executor) *FirmwareEntropyTool {
	return &FirmwareEntropyTool{exec: exec}
}

func (t *FirmwareEntropyTool) Name() string { return "firmware_entropy" }

func (t *FirmwareEntropyTool) Description() string {
	return "Analyze byte entropy across a firmware image with binwalk (-E): rising entropy edges (>= 0.95) mark compressed or encrypted regions, falling edges (<= 0.85) mark structured data such as executable code or filesystem metadata. Returns the parsed edge data plus high-entropy region spans with interpretation hints; correlate region offsets with firmware_scan signature hits to tell compression from encryption. Read-only with respect to the host system." + authorizedUseNotice
}

func (t *FirmwareEntropyTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the firmware image to analyze (must exist)"
			},
			"block": {
				"type": "integer",
				"description": "Block size in bytes for the entropy calculation (-K); binwalk auto-sizes blocks for ~2048 data points when unset (1-16777216)"
			}
		},
		"required": ["image"]
	}`)
}

type firmwareEntropyInput struct {
	Image string `json:"image"`
	Block *int64 `json:"block,omitempty"`
}

// entropyEdge is one parsed rising/falling entropy edge row.
type entropyEdge struct {
	Offset    int64   `json:"offset"`
	OffsetHex string  `json:"offset_hex"`
	Type      string  `json:"type"`
	Entropy   float64 `json:"entropy"`
}

// entropyRegion is the span between a rising edge and the next falling edge
// (or end of file): a high-entropy stretch.
type entropyRegion struct {
	StartOffset    int64  `json:"start_offset"`
	StartOffsetHex string `json:"start_offset_hex"`
	EndOffset      int64  `json:"end_offset"`
	EndOffsetHex   string `json:"end_offset_hex"`
	Interpretation string `json:"interpretation"`
}

// entropySummary is the JSON summary built from the parsed entropy CSV.
type entropySummary struct {
	Image     string          `json:"image"`
	EdgeCount int             `json:"edge_count"`
	Edges     []entropyEdge   `json:"edges"`
	Regions   []entropyRegion `json:"regions"`
}

func (t *FirmwareEntropyTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareEntropyInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateImageFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePositiveInt("block", input.Block, 1, 16777216); err != nil {
		return errorResult(err.Error()), nil
	}

	logPath, err := newCSVLog()
	if err != nil {
		return errorResult(err.Error()), nil
	}
	defer removeLog(logPath)

	args := []string{"-E", "-N", "--csv", "-f", logPath, "-q"}
	if input.Block != nil {
		args = append(args, "-K", fmt.Sprintf("%d", *input.Block))
	}
	args = append(args, input.Image)

	stdout, errResult := runBinwalk(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var edges []entropyEdge
	if data, ok := readCSVLog(logPath); ok {
		edges = parseEntropyEdges(data)
	}

	fileSize := int64(0)
	if info, err := os.Stat(input.Image); err == nil {
		fileSize = info.Size()
	}
	regions := entropyRegions(edges, fileSize)

	summary := entropySummary{
		Image:     input.Image,
		EdgeCount: len(edges),
		Edges:     edges,
		Regions:   regions,
	}
	if summary.Edges == nil {
		summary.Edges = []entropyEdge{}
	}
	if summary.Regions == nil {
		summary.Regions = []entropyRegion{}
	}

	var sb strings.Builder
	sb.WriteString("## Firmware Entropy Analysis (binwalk)\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	if input.Block != nil {
		fmt.Fprintf(&sb, "- **Block size:** %d bytes\n", *input.Block)
	}
	fmt.Fprintf(&sb, "- **Entropy edges:** %d\n", summary.EdgeCount)
	sb.WriteString("\n")

	if summary.EdgeCount == 0 {
		sb.WriteString("No entropy edges were reported: the image's entropy is uniformly moderate (between binwalk's 0.85 falling and 0.95 rising triggers) or the scan produced no data.\n\n")
	}

	if len(summary.Regions) > 0 {
		sb.WriteString("High-entropy regions (likely compressed or encrypted):\n\n")
		for _, r := range summary.Regions {
			fmt.Fprintf(&sb, "- %s-%s: %s\n", r.StartOffsetHex, r.EndOffsetHex, r.Interpretation)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### Entropy summary\n\n```json\n")
	sb.WriteString(marshalSummary(summary))
	sb.WriteString("\n```\n\n")

	if data, ok := readCSVLog(logPath); ok {
		sb.WriteString("### Raw CSV log\n\n```csv\n")
		sb.WriteString(strings.TrimSpace(string(data)))
		sb.WriteString("\n```\n")
	} else if out := strings.TrimSpace(stdout); out != "" {
		sb.WriteString("### binwalk stdout\n\n```\n")
		sb.WriteString(out)
		sb.WriteString("\n```\n")
	}

	sb.WriteString("\nInterpretation: high entropy (>= 0.95) spans are typically compressed data (squashfs, gzip, kernel images) or encrypted data (certificates, keys, obfuscated payloads); a signature hit at the same offset (see firmware_scan) indicates compression, while high entropy without a signature suggests encryption.\n")

	return textResult(sb.String()), nil
}

// parseEntropyEdges parses the entropy module's CSV rows into edges. Rows
// whose description is not a rising/falling edge line (headers, verbose
// per-block floats) are skipped.
func parseEntropyEdges(data []byte) []entropyEdge {
	var edges []entropyEdge
	for _, row := range parseBinwalkCSV(data) {
		m := entropyEdgeRegex.FindStringSubmatch(row.Description)
		if m == nil {
			continue
		}
		entropy, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		edges = append(edges, entropyEdge{
			Offset:    row.Offset,
			OffsetHex: row.OffsetHex,
			Type:      strings.ToLower(m[1]),
			Entropy:   entropy,
		})
	}
	return edges
}

// entropyRegions builds the high-entropy spans between rising edges and the
// next falling edge. binwalk's trigger logic guarantees edges alternate
// (rising, falling) in non-verbose mode. A rising edge with no following
// falling edge extends to the end of the file.
func entropyRegions(edges []entropyEdge, fileSize int64) []entropyRegion {
	var regions []entropyRegion
	open := false
	var start entropyEdge
	for _, e := range edges {
		switch e.Type {
		case "rising":
			if !open {
				start = e
				open = true
			}
		case "falling":
			if open {
				regions = append(regions, entropyRegion{
					StartOffset:    start.Offset,
					StartOffsetHex: start.OffsetHex,
					EndOffset:      e.Offset,
					EndOffsetHex:   e.OffsetHex,
					Interpretation: "high entropy between rising and falling edges; likely compressed or encrypted data",
				})
				open = false
			}
		}
	}
	if open {
		end := fileSize
		if end < start.Offset {
			end = start.Offset
		}
		regions = append(regions, entropyRegion{
			StartOffset:    start.Offset,
			StartOffsetHex: start.OffsetHex,
			EndOffset:      end,
			EndOffsetHex:   fmt.Sprintf("0x%X", end),
			Interpretation: "high entropy from this offset to end of file; likely compressed or encrypted data",
		})
	}
	return regions
}
