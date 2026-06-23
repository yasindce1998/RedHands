package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DNSLookupInput struct {
	Domain     string `json:"domain"`
	RecordType string `json:"record_type,omitempty"`
	Server     string `json:"server,omitempty"`
	Trace      bool   `json:"trace,omitempty"`
}

type DNSLookupTool struct {
	exec *executor.BinaryExecutor
}

func NewDNSLookup(exec *executor.BinaryExecutor) *DNSLookupTool {
	return &DNSLookupTool{exec: exec}
}

func (t *DNSLookupTool) Name() string { return "dns_lookup" }

func (t *DNSLookupTool) Description() string {
	return "Perform DNS lookups using dig. Supports A, AAAA, MX, NS, TXT, CNAME, SOA, ANY record types with optional trace."
}

func (t *DNSLookupTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Domain to query (e.g., example.com)"
			},
			"record_type": {
				"type": "string",
				"enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY", "PTR", "SRV"],
				"description": "DNS record type to query (default: A)"
			},
			"server": {
				"type": "string",
				"description": "DNS server to query (e.g., 8.8.8.8)"
			},
			"trace": {
				"type": "boolean",
				"description": "Enable trace mode to show full delegation path"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *DNSLookupTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DNSLookupInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateDomain(input.Domain); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Domain}

	recordType := "A"
	if input.RecordType != "" {
		recordType = strings.ToUpper(input.RecordType)
		args = append(args, recordType)
	}

	if input.Server != "" {
		if err := validateServer(input.Server); err != nil {
			return errorResult(err.Error()), nil
		}
		args = append(args, "@"+input.Server)
	}

	if input.Trace {
		args = append(args, "+trace")
	}

	args = append(args, "+noall", "+answer", "+authority", "+additional")

	result, err := t.exec.Run(ctx, "dig", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("dig execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## DNS Lookup: %s (%s)\n\n", input.Domain, recordType)
	if input.Server != "" {
		fmt.Fprintf(&sb, "Server: %s\n\n", input.Server)
	}
	if output == "" {
		sb.WriteString("No records found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
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

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(domain, c) {
			return fmt.Errorf("domain contains forbidden character: %q", c)
		}
	}
	return nil
}

func validateServer(server string) error {
	if len(server) > 253 {
		return fmt.Errorf("server too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(server, c) {
			return fmt.Errorf("server contains forbidden character: %q", c)
		}
	}
	return nil
}
