package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var rangeActions = []string{"up", "list"}

// RangeTool wraps `barzakh-scanner range up` and `range list` (verified
// against scanner main.rs):
//
//	range up --suite <name|path> [--range-dir <dir>] [--dry-run] [--keep]
//	         [--skip-memory-scan] [--json]
//	range list [--range-dir <dir>]
//
// `range up` boots a real QEMU/OVMF/swtpm VM per suite case, deploys
// payloads, captures guest memory, scans it and asserts the expected
// detections; it is long-running and bounded by the executor timeout
// (REDHANDS_TIMEOUT, default 300s) unless --dry-run is used. It exits 1 when
// the suite's assertions fail (report.pass == false — a detection coverage
// result, not an execution failure) and 2 on real errors (scanner main()).
// `range list` is a read-only directory listing.
type RangeInput struct {
	Action         string `json:"action"`
	Suite          string `json:"suite,omitempty"`
	RangeDir       string `json:"range_dir,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
	Keep           bool   `json:"keep,omitempty"`
	SkipMemoryScan bool   `json:"skip_memory_scan,omitempty"`
	JSON           bool   `json:"json,omitempty"`
}

type RangeTool struct {
	exec executor.Executor
}

func NewRange(exec executor.Executor) *RangeTool {
	return &RangeTool{exec: exec}
}

func (t *RangeTool) Name() string { return "barzakh_range" }

func (t *RangeTool) Description() string {
	return "Boot QEMU/OVMF/swtpm cyber-range suites that deploy adversary payloads on real VMs, capture guest memory, scan it and assert the expected detections (attack → detect → assert). up runs a suite manifest by name or path (use dry_run to validate manifests and plan the VM without booting anything); list shows the suites available in a manifest directory. up is long-running and bounded by the executor timeout (REDHANDS_TIMEOUT, default 300s). A suite whose assertions fail (scanner exit code 1 — expected detections did not fire) is reported as a result, not an error; exit code 2 is a real error. HIGH IMPACT: boots implanted firmware in emulated environments for authorized lab use only; approval-gated."
}

func (t *RangeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["up", "list"],
				"description": "up: boot a range suite and assert detections; list: list available suites"
			},
			"suite": {
				"type": "string",
				"description": "Suite manifest: a path to a range/*.toml file or a name resolved inside range_dir (required for up)"
			},
			"range_dir": {
				"type": "string",
				"description": "Directory holding range/*.toml manifests (default: range)"
			},
			"dry_run": {
				"type": "boolean",
				"description": "Validate manifests, generate payloads and plan the VM without booting anything (works without QEMU installed)"
			},
			"keep": {
				"type": "boolean",
				"description": "Keep the per-case artifact directories (serial logs, memory dumps)"
			},
			"skip_memory_scan": {
				"type": "boolean",
				"description": "Skip the slow guest-memory scan; assert on deployment artifacts only"
			},
			"json": {
				"type": "boolean",
				"description": "Emit the suite report as JSON (up only)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *RangeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RangeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if !isValidAction(rangeActions, input.Action) {
		return errorResult("invalid action: must be one of " + strings.Join(rangeActions, ", ")), nil
	}
	if input.Action == "up" && input.Suite == "" {
		return errorResult("suite is required for up"), nil
	}
	if err := validateSafeString(input.Suite, "suite"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.RangeDir, "range_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "up":
		args = []string{"range", "up", "--suite", input.Suite}
		if input.RangeDir != "" {
			args = append(args, "--range-dir", input.RangeDir)
		}
		if input.DryRun {
			args = append(args, "--dry-run")
		}
		if input.Keep {
			args = append(args, "--keep")
		}
		if input.SkipMemoryScan {
			args = append(args, "--skip-memory-scan")
		}
		if input.JSON {
			args = append(args, "--json")
		}
	case "list":
		args = []string{"range", "list"}
		if input.RangeDir != "" {
			args = append(args, "--range-dir", input.RangeDir)
		}
	}

	// `range up` exits 1 when the suite's assertions fail (expected
	// detections did not fire) — a valid coverage result with the report on
	// stdout, not a failure. Exit 2 (scanner main's error path) stays an
	// error.
	result, suiteFailed, err := runWithDetectionExit(ctx, t.exec, exitCodeDetection, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner range %s failed (exit code 2 is a real error): %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Barzakh Cyber Range\n\n")
	fmt.Fprintf(&sb, "- **Action:** %s\n", input.Action)
	if input.Suite != "" {
		fmt.Fprintf(&sb, "- **Suite:** %s\n", input.Suite)
	}
	if input.RangeDir != "" {
		fmt.Fprintf(&sb, "- **Range dir:** %s\n", input.RangeDir)
	}
	if input.Action == "up" {
		if suiteFailed {
			sb.WriteString("- **Result:** ⚠️ suite FAILED — expected detections did not fire (coverage gap; scanner exit code 1)\n")
		} else {
			sb.WriteString("- **Result:** suite passed (all expected detections asserted)\n")
		}
	}
	sb.WriteString("\n")

	if output == "" {
		sb.WriteString("Range command completed (no output).\n")
	} else if input.Action == "up" && input.JSON {
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
