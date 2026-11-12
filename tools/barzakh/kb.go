package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

var kbActions = []string{"add", "list", "search", "export", "import"}

// KbTool wraps `barzakh-scanner kb add|list|search|export|import` (verified
// against scanner main.rs):
//
//	kb add --target <image> [--vendor V] [--device D] [--family F]
//	       [--fw-version V] [--arch A] [--notes N] [--known-clean] [--db <sqlite>]
//	kb list [--db <sqlite>]
//	kb search --query <text> [--db <sqlite>]
//	kb export --output <json> [--anonymize] [--db <sqlite>]
//	kb import --input <json> [--db <sqlite>]
//
// --arch in `kb add` is free-form metadata (Option<String>), unlike the
// arch enums elsewhere. --db defaults to barzakh-kb.sqlite. list/search are
// read-only; add/export/import mutate the knowledge base. The scanner
// main() exits 2 on error, so no detection-exit handling is needed.
type KbInput struct {
	Action     string `json:"action"`
	Target     string `json:"target,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Device     string `json:"device,omitempty"`
	Family     string `json:"family,omitempty"`
	FwVersion  string `json:"fw_version,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Notes      string `json:"notes,omitempty"`
	KnownClean bool   `json:"known_clean,omitempty"`
	DB         string `json:"db,omitempty"`
	Query      string `json:"query,omitempty"`
	Output     string `json:"output,omitempty"`
	Anonymize  bool   `json:"anonymize,omitempty"`
	Input      string `json:"input,omitempty"`
}

type KbTool struct {
	exec executor.Executor
}

func NewKb(exec executor.Executor) *KbTool {
	return &KbTool{exec: exec}
}

func (t *KbTool) Name() string { return "barzakh_kb" }

func (t *KbTool) Description() string {
	return "Manage the firmware knowledge base (SQLite): add a firmware profile from an image (hash, size, optional vendor/device/family/version/arch metadata, known-clean marking), list all profiles, search vendor/device/family/notes/hash prefixes, export profiles as a shareable JSON bundle (optionally anonymized), or import a profile bundle. list and search are read-only; add, export and import write."
}

func (t *KbTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["add", "list", "search", "export", "import"],
				"description": "record a profile, list profiles, search profiles, export a JSON bundle, or import a bundle"
			},
			"target": {
				"type": "string",
				"description": "Firmware image to profile (required for add; must exist)"
			},
			"vendor": {
				"type": "string",
				"description": "Vendor metadata (add only)"
			},
			"device": {
				"type": "string",
				"description": "Device metadata (add only)"
			},
			"family": {
				"type": "string",
				"description": "Firmware family metadata (add only)"
			},
			"fw_version": {
				"type": "string",
				"description": "Firmware version string, e.g. \"3607\" (add only)"
			},
			"arch": {
				"type": "string",
				"description": "Architecture metadata, free-form (add only)"
			},
			"notes": {
				"type": "string",
				"description": "Free-form notes (add only)"
			},
			"known_clean": {
				"type": "boolean",
				"description": "Mark the image as verified known-clean (add only)"
			},
			"db": {
				"type": "string",
				"description": "Knowledge base path (default: barzakh-kb.sqlite)"
			},
			"query": {
				"type": "string",
				"description": "Search text for vendor/device/family/notes/hash prefixes (required for search)"
			},
			"output": {
				"type": "string",
				"description": "Output path for the exported JSON bundle (required for export)"
			},
			"anonymize": {
				"type": "boolean",
				"description": "Strip identifying vendor/device details on export"
			},
			"input": {
				"type": "string",
				"description": "Profile bundle JSON to import (required for import; must exist)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *KbTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KbInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if !isValidAction(kbActions, input.Action) {
		return errorResult("invalid action: must be one of " + strings.Join(kbActions, ", ")), nil
	}
	for field, value := range map[string]string{
		"vendor":     input.Vendor,
		"device":     input.Device,
		"family":     input.Family,
		"fw_version": input.FwVersion,
		"arch":       input.Arch,
		"notes":      input.Notes,
		"query":      input.Query,
	} {
		if err := validateSafeString(value, field); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validatePath(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.DB, "db"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Output, "output"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Input, "input"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "add":
		if input.Target == "" {
			return errorResult("target is required for add"), nil
		}
		if err := validateExistingFile(input.Target, "target"); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"kb", "add", "--target", input.Target}
		if input.Vendor != "" {
			args = append(args, "--vendor", input.Vendor)
		}
		if input.Device != "" {
			args = append(args, "--device", input.Device)
		}
		if input.Family != "" {
			args = append(args, "--family", input.Family)
		}
		if input.FwVersion != "" {
			args = append(args, "--fw-version", input.FwVersion)
		}
		if input.Arch != "" {
			args = append(args, "--arch", input.Arch)
		}
		if input.Notes != "" {
			args = append(args, "--notes", input.Notes)
		}
		if input.KnownClean {
			args = append(args, "--known-clean")
		}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "list":
		args = []string{"kb", "list"}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "search":
		if input.Query == "" {
			return errorResult("query is required for search"), nil
		}
		args = []string{"kb", "search", "--query", input.Query}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "export":
		if input.Output == "" {
			return errorResult("output is required for export"), nil
		}
		args = []string{"kb", "export", "--output", input.Output}
		if input.Anonymize {
			args = append(args, "--anonymize")
		}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	case "import":
		if input.Input == "" {
			return errorResult("input is required for import"), nil
		}
		if err := validateExistingFile(input.Input, "input"); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"kb", "import", "--input", input.Input}
		if input.DB != "" {
			args = append(args, "--db", input.DB)
		}
	}

	result, err := t.exec.Run(ctx, "barzakh-scanner", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner kb %s failed: %s\n%s", input.Action, err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Knowledge Base: %s\n\n", input.Action)
	if input.DB != "" {
		fmt.Fprintf(&sb, "- **DB:** %s\n", input.DB)
	}
	switch input.Action {
	case "add":
		fmt.Fprintf(&sb, "- **Target:** %s\n", input.Target)
		if input.KnownClean {
			sb.WriteString("- **Known clean:** yes\n")
		}
	case "search":
		fmt.Fprintf(&sb, "- **Query:** %s\n", input.Query)
	case "export":
		fmt.Fprintf(&sb, "- **Output:** %s\n", input.Output)
		if input.Anonymize {
			sb.WriteString("- **Anonymized:** yes\n")
		}
	case "import":
		fmt.Fprintf(&sb, "- **Input:** %s\n", input.Input)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Knowledge base command completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
