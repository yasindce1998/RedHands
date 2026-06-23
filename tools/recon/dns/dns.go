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
	Domain       string `json:"domain"`
	RecordType   string `json:"record_type,omitempty"`
	Server       string `json:"server,omitempty"`
	Trace        bool   `json:"trace,omitempty"`
	ZoneTransfer bool   `json:"zone_transfer,omitempty"`
	Reverse      bool   `json:"reverse,omitempty"`
	Short        bool   `json:"short,omitempty"`
	TCP          bool   `json:"tcp,omitempty"`
	Timeout      int    `json:"timeout,omitempty"`
	Retries      int    `json:"retries,omitempty"`
	AllRecords   bool   `json:"all_records,omitempty"`
}

type DNSLookupTool struct {
	exec executor.Executor
}

func NewDNSLookup(exec executor.Executor) *DNSLookupTool {
	return &DNSLookupTool{exec: exec}
}

func (t *DNSLookupTool) Name() string { return "dns_lookup" }

func (t *DNSLookupTool) Description() string {
	return "Perform DNS lookups using dig. Supports record types (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY, PTR, SRV), zone transfers (AXFR), reverse lookups, short output, TCP mode, and custom timeouts."
}

func (t *DNSLookupTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Domain or IP to query (e.g., example.com or 8.8.8.8 for reverse)"
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
			},
			"zone_transfer": {
				"type": "boolean",
				"description": "Attempt AXFR zone transfer (requires server)"
			},
			"reverse": {
				"type": "boolean",
				"description": "Perform reverse DNS lookup (-x) on an IP address"
			},
			"short": {
				"type": "boolean",
				"description": "Short output mode (+short) — only show answer values"
			},
			"tcp": {
				"type": "boolean",
				"description": "Use TCP instead of UDP (+tcp)"
			},
			"timeout": {
				"type": "integer",
				"description": "Query timeout in seconds (default: 5)"
			},
			"retries": {
				"type": "integer",
				"description": "Number of retries (default: 3)"
			},
			"all_records": {
				"type": "boolean",
				"description": "Query ALL record types (equivalent to record_type=ANY)"
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

	if input.ZoneTransfer && input.Reverse {
		return errorResult("zone_transfer and reverse are mutually exclusive"), nil
	}

	var args []string
	recordType := "A"

	if input.Reverse {
		args = append(args, "-x", input.Domain)
		recordType = "PTR"
	} else if input.ZoneTransfer {
		args = append(args, "AXFR", input.Domain)
		recordType = "AXFR"
	} else {
		args = append(args, input.Domain)
		if input.AllRecords {
			recordType = "ANY"
			args = append(args, "ANY")
		} else if input.RecordType != "" {
			recordType = strings.ToUpper(input.RecordType)
			args = append(args, recordType)
		}
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
	if input.Short {
		args = append(args, "+short")
	} else {
		args = append(args, "+noall", "+answer", "+authority", "+additional")
	}
	if input.TCP {
		args = append(args, "+tcp")
	}
	if input.Timeout > 0 {
		args = append(args, fmt.Sprintf("+time=%d", input.Timeout))
	}
	if input.Retries > 0 {
		args = append(args, fmt.Sprintf("+tries=%d", input.Retries))
	}

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
