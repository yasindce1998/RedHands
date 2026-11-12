package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// telecom_firmware_patch — modem-firmware patch (HIGH IMPACT)
// ---------------------------------------------------------------------------

// FirmwarePatchTool runs `modem-firmware patch`: applies a JSON patch
// specification (offset + expected original bytes + replacement bytes per
// patch) to a baseband firmware image and writes the patched image.
// Verified against tools/src/modem_firmware.rs: the Patch subcommand takes
// exactly --image, --patchfile and --output (all required, no defaults), and
// the analyzer is hardcoded to the qualcomm profile for patching.
type FirmwarePatchTool struct {
	exec executor.Executor
}

func NewFirmwarePatch(exec executor.Executor) *FirmwarePatchTool {
	return &FirmwarePatchTool{exec: exec}
}

func (t *FirmwarePatchTool) Name() string { return "telecom_firmware_patch" }

func (t *FirmwarePatchTool) Description() string {
	return "Patch a modem/baseband firmware image by applying a JSON patch specification (modem-firmware patch): each patch entry gives a byte offset, the expected original bytes, and replacement bytes; entries whose original bytes do not match (or that extend past the image end) are skipped with a warning, and the patched image is written to the output path. HIGH IMPACT: produces a modified baseband firmware image that alters modem behavior when flashed; only patch images you are authorized to modify in an isolated lab, and never flash patched images to devices on live networks. Approval-gated." + authorizedUseNotice
}

func (t *FirmwarePatchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"image": {
				"type": "string",
				"description": "Path to the original firmware image (.mbn, .elf, .bin; must exist)"
			},
			"patchfile": {
				"type": "string",
				"description": "Path to the JSON patch specification (must exist): {\"patches\":[{\"offset\":<u64>,\"original\":[<bytes 0-255>],\"replacement\":[<bytes 0-255>],\"description\":\"...\"}],\"description\":\"...\"}"
			},
			"output": {
				"type": "string",
				"description": "Output path for the patched image (required; overwritten if it exists)"
			}
		},
		"required": ["image", "patchfile", "output"]
	}`)
}

type firmwarePatchInput struct {
	Image     string `json:"image"`
	Patchfile string `json:"patchfile"`
	Output    string `json:"output"`
}

// patchSpecProbe mirrors the required fields of modem-firmware's PatchSpec
// (serde requires every field, so pointer presence checks approximate the
// Rust parse errors without duplicating them).
type patchSpecProbe struct {
	Patches []struct {
		Offset      *uint64 `json:"offset"`
		Original    *[]byte `json:"original"`
		Replacement *[]byte `json:"replacement"`
	} `json:"patches"`
}

// validatePatchSpec parses the patch specification file and rejects files the
// Rust PatchSpec deserializer would reject (missing patches array, missing
// per-patch fields, or byte values outside 0-255), failing fast before the
// binary runs.
func validatePatchSpec(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("patchfile not readable: %v", err)
	}
	var spec patchSpecProbe
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("invalid patchfile: not valid JSON (%v)", err)
	}
	if spec.Patches == nil {
		return fmt.Errorf("invalid patchfile: missing required \"patches\" array")
	}
	for i, p := range spec.Patches {
		if p.Offset == nil {
			return fmt.Errorf("invalid patchfile: patch %d is missing \"offset\"", i)
		}
		if p.Original == nil {
			return fmt.Errorf("invalid patchfile: patch %d is missing \"original\"", i)
		}
		if p.Replacement == nil {
			return fmt.Errorf("invalid patchfile: patch %d is missing \"replacement\"", i)
		}
	}
	return nil
}

func (t *FirmwarePatchTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwarePatchInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInputFile(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateInputFile(input.Patchfile, "patchfile"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Output == "" {
		return errorResult("output is required"), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePatchSpec(input.Patchfile); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"patch", "--image", input.Image, "--patchfile", input.Patchfile, "--output", input.Output}

	stdout, errResult := runModemFirmware(ctx, t.exec, args)
	if errResult != nil {
		return errResult, nil
	}

	var sb strings.Builder
	sb.WriteString("## Modem Firmware Patch (HIGH IMPACT)\n\n")
	fmt.Fprintf(&sb, "- **Image:** %s\n", input.Image)
	fmt.Fprintf(&sb, "- **Patch specification:** %s\n", input.Patchfile)
	fmt.Fprintf(&sb, "- **Patched image:** %s\n", input.Output)
	sb.WriteString("\n")
	if info, err := os.Stat(input.Output); err == nil && !info.IsDir() {
		fmt.Fprintf(&sb, "- **Patched image size:** %d bytes\n\n", info.Size())
	} else {
		sb.WriteString("- The patched image file was not readable after the run; check the log below.\n\n")
	}
	sb.WriteString("### Patch log\n\n```\n")
	log := strings.TrimSpace(stdout)
	if log == "" {
		log = "Patch completed (no output)."
	}
	sb.WriteString(log)
	sb.WriteString("\n```\n")
	sb.WriteString("\nFlashing patched baseband firmware is regulated and device-destructive; authorized, isolated lab use only.\n")

	return textResult(sb.String()), nil
}
