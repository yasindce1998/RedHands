package hashcat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CrackInput struct {
	HashFile   string `json:"hash_file"`
	HashType   int    `json:"hash_type"`
	AttackMode int    `json:"attack_mode,omitempty"`
	Wordlist   string `json:"wordlist,omitempty"`
	Rules      string `json:"rules,omitempty"`
	Mask       string `json:"mask,omitempty"`
	Potfile    string `json:"potfile,omitempty"`
	Outfile    string `json:"outfile,omitempty"`
}

type CrackTool struct {
	exec executor.Executor
}

func NewCrack(exec executor.Executor) *CrackTool {
	return &CrackTool{exec: exec}
}

func (t *CrackTool) Name() string { return "hashcat_crack" }

func (t *CrackTool) Description() string {
	return "Crack password hashes using Hashcat with GPU acceleration. Supports dictionary, brute-force, combination, and rule-based attacks against 300+ hash types."
}

func (t *CrackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hash_file": {
				"type": "string",
				"description": "Path to file containing hashes"
			},
			"hash_type": {
				"type": "integer",
				"description": "Hash type code (e.g., 0=MD5, 1000=NTLM, 1800=sha512crypt)"
			},
			"attack_mode": {
				"type": "integer",
				"description": "Attack mode (0=dictionary, 1=combination, 3=brute-force, 6=hybrid)"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to wordlist file"
			},
			"rules": {
				"type": "string",
				"description": "Path to rules file"
			},
			"mask": {
				"type": "string",
				"description": "Mask for brute-force (e.g., ?a?a?a?a?a?a)"
			},
			"potfile": {
				"type": "string",
				"description": "Path to potfile"
			},
			"outfile": {
				"type": "string",
				"description": "Output file for cracked hashes"
			}
		},
		"required": ["hash_file", "hash_type"]
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
	if err := validateSafeString(input.Wordlist, "wordlist"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Rules, "rules"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Mask, "mask"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Potfile, "potfile"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Outfile, "outfile"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-m", fmt.Sprintf("%d", input.HashType)}
	if input.AttackMode > 0 {
		args = append(args, "-a", fmt.Sprintf("%d", input.AttackMode))
	}
	if input.Rules != "" {
		args = append(args, "-r", input.Rules)
	}
	if input.Potfile != "" {
		args = append(args, "--potfile-path", input.Potfile)
	}
	if input.Outfile != "" {
		args = append(args, "-o", input.Outfile)
	}
	args = append(args, input.HashFile)
	if input.Wordlist != "" {
		args = append(args, input.Wordlist)
	}
	if input.Mask != "" {
		args = append(args, input.Mask)
	}

	result, err := t.exec.Run(ctx, "hashcat", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("hashcat failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Hashcat Crack\n\n")
	fmt.Fprintf(&sb, "**Hash Type**: %d | **File**: %s\n\n", input.HashType, input.HashFile)
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
