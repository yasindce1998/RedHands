package john

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CrackInput struct {
	HashFile string `json:"hash_file"`
	Format   string `json:"format,omitempty"`
	Wordlist string `json:"wordlist,omitempty"`
	Rules    string `json:"rules,omitempty"`
	Mask     string `json:"mask,omitempty"`
	Session  string `json:"session,omitempty"`
}

type CrackTool struct {
	exec executor.Executor
}

func NewCrack(exec executor.Executor) *CrackTool {
	return &CrackTool{exec: exec}
}

func (t *CrackTool) Name() string { return "john_crack" }

func (t *CrackTool) Description() string {
	return "Crack password hashes using John the Ripper. Supports wordlist, incremental, and mask modes with auto-detection of hash formats."
}

func (t *CrackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hash_file": {
				"type": "string",
				"description": "Path to file containing hashes"
			},
			"format": {
				"type": "string",
				"description": "Hash format (e.g., NT, raw-md5, bcrypt)"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to wordlist"
			},
			"rules": {
				"type": "string",
				"description": "Rules section name"
			},
			"mask": {
				"type": "string",
				"description": "Mask for brute-force mode"
			},
			"session": {
				"type": "string",
				"description": "Session name for resuming"
			}
		},
		"required": ["hash_file"]
	}`)
}

func (t *CrackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CrackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.HashFile, "hash_file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Format, "format"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Wordlist, "wordlist"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Rules, "rules"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Mask, "mask"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Session, "session"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{}
	if input.Format != "" {
		args = append(args, fmt.Sprintf("--format=%s", input.Format))
	}
	if input.Wordlist != "" {
		args = append(args, fmt.Sprintf("--wordlist=%s", input.Wordlist))
	}
	if input.Rules != "" {
		args = append(args, fmt.Sprintf("--rules=%s", input.Rules))
	}
	if input.Mask != "" {
		args = append(args, fmt.Sprintf("--mask=%s", input.Mask))
	}
	if input.Session != "" {
		args = append(args, fmt.Sprintf("--session=%s", input.Session))
	}
	args = append(args, input.HashFile)

	result, err := t.exec.Run(ctx, "john", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("john failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## John the Ripper\n\n")
	fmt.Fprintf(&sb, "**File**: %s\n\n", input.HashFile)
	if output == "" {
		sb.WriteString("Cracking complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
