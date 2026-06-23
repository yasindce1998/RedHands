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
	Domain   string `json:"domain,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Passive  bool   `json:"passive,omitempty"`
	ASN      string `json:"asn,omitempty"`
	CIDR     string `json:"cidr,omitempty"`
	Whois    bool   `json:"whois,omitempty"`
	Org      string `json:"org,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Config   string `json:"config,omitempty"`
	MaxDepth int    `json:"max_depth,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
	Brute    bool   `json:"brute,omitempty"`
}

type ASNEnumTool struct {
	exec executor.Executor
}

func NewASNEnum(exec executor.Executor) *ASNEnumTool {
	return &ASNEnumTool{exec: exec}
}

func (t *ASNEnumTool) Name() string { return "amass_enum" }

func (t *ASNEnumTool) Description() string {
	return "Network mapping and external asset discovery using OWASP Amass. Supports enum mode (DNS enumeration) and intel mode (organization/infrastructure discovery via WHOIS, ASN, CIDR)."
}

func (t *ASNEnumTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Target domain for enumeration (e.g., example.com)"
			},
			"mode": {
				"type": "string",
				"enum": ["enum", "intel"],
				"description": "Amass mode: 'enum' for DNS enumeration (default), 'intel' for organization/infrastructure discovery"
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
			},
			"whois": {
				"type": "boolean",
				"description": "Intel mode: use reverse WHOIS for discovery"
			},
			"org": {
				"type": "string",
				"description": "Intel mode: search by organization name"
			},
			"addr": {
				"type": "string",
				"description": "Intel mode: investigate IP address(es)"
			},
			"config": {
				"type": "string",
				"description": "Path to Amass configuration file"
			},
			"max_depth": {
				"type": "integer",
				"description": "Maximum DNS enumeration depth"
			},
			"timeout": {
				"type": "integer",
				"description": "Timeout in minutes for the enumeration"
			},
			"brute": {
				"type": "boolean",
				"description": "Enable brute-force subdomain enumeration"
			}
		}
	}`)
}

func (t *ASNEnumTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ASNEnumInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	mode := "enum"
	if input.Mode != "" {
		mode = input.Mode
	}

	var args []string

	switch mode {
	case "intel":
		args = []string{"intel"}
		if input.Domain != "" {
			if err := validateInput(input.Domain); err != nil {
				return errorResult(err.Error()), nil
			}
			args = append(args, "-d", input.Domain)
		}
		if input.Whois {
			args = append(args, "-whois")
		}
		if input.Org != "" {
			if err := validateInput(input.Org); err != nil {
				return errorResult("invalid org: " + err.Error()), nil
			}
			args = append(args, "-org", input.Org)
		}
		if input.Addr != "" {
			if err := validateInput(input.Addr); err != nil {
				return errorResult("invalid addr: " + err.Error()), nil
			}
			args = append(args, "-addr", input.Addr)
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
	default:
		if input.Domain == "" {
			return errorResult("domain is required for enum mode"), nil
		}
		if err := validateInput(input.Domain); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{"enum", "-d", input.Domain}
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
		if input.Brute {
			args = append(args, "-brute")
		}
		if input.MaxDepth > 0 {
			args = append(args, "-max-depth", fmt.Sprintf("%d", input.MaxDepth))
		}
	}

	if input.Config != "" {
		args = append(args, "-config", input.Config)
	}
	if input.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", input.Timeout))
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

	target := input.Domain
	if target == "" {
		target = input.Org
	}
	if target == "" {
		target = input.ASN
	}

	var sb strings.Builder
	modeTitle := "Enum"
	if mode == "intel" {
		modeTitle = "Intel"
	}
	fmt.Fprintf(&sb, "## Amass %s: %s\n\n", modeTitle, target)
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
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(val, c) {
			return fmt.Errorf("value contains forbidden character: %q", c)
		}
	}
	return nil
}
