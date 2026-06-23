package amass

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ASNEnumInput struct {
	Domain  string `json:"domain"`
	Passive bool   `json:"passive,omitempty"`
	ASN     string `json:"asn,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
}

type ASNEnumTool struct {
	exec *executor.BinaryExecutor
}

func NewASNEnum(exec *executor.BinaryExecutor) *ASNEnumTool {
	return &ASNEnumTool{exec: exec}
}

func (t *ASNEnumTool) Name() string { return "amass_enum" }

func (t *ASNEnumTool) Description() string {
	return "Network mapping and external asset discovery using OWASP Amass. Performs DNS enumeration, ASN discovery, and infrastructure mapping."
}

func (t *ASNEnumTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Target domain for enumeration (e.g., example.com)"
			},
			"passive": {
				"type": "boolean",
				"description": "Passive mode only (no DNS resolution or active probing)"
			},
			"asn": {
				"type": "string",
				"description": "ASN number to investigate (e.g., 'AS13335')"
			},
			"cidr": {
				"type": "string",
				"description": "CIDR range to investigate (e.g., '192.168.1.0/24')"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *ASNEnumTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ASNEnumInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Domain); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"enum", "-d", input.Domain}

	if input.Passive {
		args = append(args, "-passive")
	}
	if input.ASN != "" {
		if err := validateInput(input.ASN); err != nil {
			return errorResult("invalid ASN: " + err.Error()), nil
		}
		args = append(args, "-asn", input.ASN)
	}
	if input.CIDR != "" {
		if err := validateInput(input.CIDR); err != nil {
			return errorResult("invalid CIDR: " + err.Error()), nil
		}
		args = append(args, "-cidr", input.CIDR)
	}

	result, err := t.exec.Run(ctx, "amass", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("amass execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var filtered []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			filtered = append(filtered, l)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Amass Enumeration: %s\n\n", input.Domain)
	if input.Passive {
		sb.WriteString("Mode: Passive\n\n")
	}
	fmt.Fprintf(&sb, "Found %d result(s):\n\n", len(filtered))
	for _, l := range filtered {
		fmt.Fprintf(&sb, "- %s\n", l)
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func validateInput(val string) error {
	if val == "" {
		return fmt.Errorf("value is required")
	}
	if len(val) > 253 {
		return fmt.Errorf("value too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(val, c) {
			return fmt.Errorf("value contains forbidden character: %q", c)
		}
	}
	return nil
}
