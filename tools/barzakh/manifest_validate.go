package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// manifestValidateSplits mirrors the value_parser of scanner validate's
// --split flag: train, validation, test.
var manifestValidateSplits = []string{"train", "validation", "test"}

// ManifestValidateTool wraps `barzakh-scanner validate --manifest` (verified
// against scanner main.rs):
//
//	validate --corpus <dir> --manifest <toml> [--strict]
//	         [--split train|validation|test] [--baseline <json>]
//
// This is the scanner-side manifest validation, materially different from
// barzakh_validate (which wraps barzakh-adversary validate): it evaluates the
// scanner's own detectors against an explicitly labeled corpus TOML (paths
// relative to the manifest), can require every declared sample and both
// positive/negative classes (--strict), and can evaluate one held-out split
// (--split). --corpus is still required by the CLI even in manifest mode.
// cmd_validate always returns Ok (the report goes to stdout); the scanner
// main() exits 2 on error, so no detection-exit handling is needed.
type ManifestValidateInput struct {
	Corpus   string `json:"corpus"`
	Manifest string `json:"manifest"`
	Strict   bool   `json:"strict,omitempty"`
	Split    string `json:"split,omitempty"`
	Baseline string `json:"baseline,omitempty"`
}

type ManifestValidateTool struct {
	exec executor.Executor
}

func NewManifestValidate(exec executor.Executor) *ManifestValidateTool {
	return &ManifestValidateTool{exec: exec}
}

func (t *ManifestValidateTool) Name() string { return "barzakh_manifest_validate" }

func (t *ManifestValidateTool) Description() string {
	return "Validate scanner detection accuracy against an explicitly labeled corpus manifest (TOML with sample paths, labels and hashes): verifies that malicious samples are detected and clean samples are not, optionally requiring every declared sample and both classes (strict), or evaluating one held-out split (train, validation, or test). Read-only analysis; unlike barzakh_validate this evaluates the scanner's detectors against explicit labels rather than filename heuristics."
}

func (t *ManifestValidateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"corpus": {
				"type": "string",
				"description": "Corpus directory the manifest paths are resolved against (must exist)"
			},
			"manifest": {
				"type": "string",
				"description": "Path to the labeled corpus TOML manifest (must exist)"
			},
			"strict": {
				"type": "boolean",
				"description": "Require every declared sample and both positive/negative classes"
			},
			"split": {
				"type": "string",
				"enum": ["train", "validation", "test"],
				"description": "Evaluate one held-out split of the manifest"
			},
			"baseline": {
				"type": "string",
				"description": "Optional baseline JSON applied during validation scans"
			}
		},
		"required": ["corpus", "manifest"]
	}`)
}

func (t *ManifestValidateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ManifestValidateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Corpus == "" {
		return errorResult("corpus path is required"), nil
	}
	if err := validatePath(input.Corpus, "corpus"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingDir(input.Corpus, "corpus"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Manifest == "" {
		return errorResult("manifest path is required"), nil
	}
	if err := validatePath(input.Manifest, "manifest"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateExistingFile(input.Manifest, "manifest"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Baseline, "baseline"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Split != "" && !isValidAction(manifestValidateSplits, input.Split) {
		return errorResult("invalid split: must be one of " + strings.Join(manifestValidateSplits, ", ")), nil
	}

	args := []string{"validate", "--corpus", input.Corpus, "--manifest", input.Manifest}
	if input.Strict {
		args = append(args, "--strict")
	}
	if input.Split != "" {
		args = append(args, "--split", input.Split)
	}
	if input.Baseline != "" {
		args = append(args, "--baseline", input.Baseline)
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner validate --manifest failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Manifest Validation Results\n\n")
	fmt.Fprintf(&sb, "- **Corpus:** %s\n", input.Corpus)
	fmt.Fprintf(&sb, "- **Manifest:** %s\n", input.Manifest)
	if input.Strict {
		sb.WriteString("- **Strict:** yes\n")
	}
	if input.Split != "" {
		fmt.Fprintf(&sb, "- **Split:** %s\n", input.Split)
	}
	if input.Baseline != "" {
		fmt.Fprintf(&sb, "- **Baseline:** %s\n", input.Baseline)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Validation completed (no output).\n")
	} else {
		sb.WriteString("```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
