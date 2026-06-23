package testssl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type TLSScanInput struct {
	Host        string `json:"host"`
	Port        int    `json:"port,omitempty"`
	StartTLS    string `json:"starttls,omitempty"`
	Protocols   bool   `json:"protocols,omitempty"`
	Ciphers     bool   `json:"ciphers,omitempty"`
	Vulns       bool   `json:"vulnerabilities,omitempty"`
	Headers     bool   `json:"headers,omitempty"`
	CertInfo    bool   `json:"cert_info,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Parallel    bool   `json:"parallel,omitempty"`
	Fast        bool   `json:"fast,omitempty"`
	Sneaky      bool   `json:"sneaky,omitempty"`
	IP          string `json:"ip,omitempty"`
	Warnings    bool   `json:"warnings,omitempty"`
	Quiet       bool   `json:"quiet,omitempty"`
	Full        bool   `json:"full,omitempty"`
	OpenSSLPath string `json:"openssl_path,omitempty"`
}

type TLSScanTool struct {
	exec executor.Executor
}

func NewTLSScan(exec executor.Executor) *TLSScanTool {
	return &TLSScanTool{exec: exec}
}

func (t *TLSScanTool) Name() string { return "testssl_scan" }

func (t *TLSScanTool) Description() string {
	return "Test TLS/SSL encryption on a server. Checks protocols, cipher suites, vulnerabilities (BEAST, POODLE, Heartbleed, etc.), and certificate details. Supports severity filtering, parallel testing, and custom OpenSSL paths."
}

func (t *TLSScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host (e.g., 'example.com' or 'example.com:8443')"
			},
			"port": {
				"type": "integer",
				"description": "Port to test (default: 443)"
			},
			"starttls": {
				"type": "string",
				"enum": ["smtp", "pop3", "imap", "ftp", "xmpp", "ldap", "postgres", "mysql"],
				"description": "STARTTLS protocol to use"
			},
			"protocols": {
				"type": "boolean",
				"description": "Check supported TLS/SSL protocols"
			},
			"ciphers": {
				"type": "boolean",
				"description": "Check cipher suites"
			},
			"vulnerabilities": {
				"type": "boolean",
				"description": "Check for TLS vulnerabilities (Heartbleed, CCS, ROBOT, etc.)"
			},
			"headers": {
				"type": "boolean",
				"description": "Check HTTP security headers (HSTS, etc.)"
			},
			"cert_info": {
				"type": "boolean",
				"description": "Display certificate information"
			},
			"severity": {
				"type": "string",
				"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
				"description": "Minimum severity level to display in output"
			},
			"parallel": {
				"type": "boolean",
				"description": "Run tests in parallel (faster but more connections)"
			},
			"fast": {
				"type": "boolean",
				"description": "Skip some checks for faster results"
			},
			"sneaky": {
				"type": "boolean",
				"description": "Be less aggressive, slower but stealthier"
			},
			"ip": {
				"type": "string",
				"description": "Specify IP address to test (useful when host resolves to multiple IPs)"
			},
			"warnings": {
				"type": "boolean",
				"description": "Suppress warning messages (batch mode)"
			},
			"quiet": {
				"type": "boolean",
				"description": "Quiet mode — minimal output"
			},
			"full": {
				"type": "boolean",
				"description": "Run all tests (full scan)"
			},
			"openssl_path": {
				"type": "string",
				"description": "Path to custom OpenSSL binary"
			}
		},
		"required": ["host"]
	}`)
}

func (t *TLSScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TLSScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateHost(input.Host); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"--color", "0"}

	if input.StartTLS != "" {
		args = append(args, "--starttls", input.StartTLS)
	}
	if input.Protocols {
		args = append(args, "-p")
	}
	if input.Ciphers {
		args = append(args, "-E")
	}
	if input.Vulns {
		args = append(args, "-U")
	}
	if input.Headers {
		args = append(args, "-h")
	}
	if input.CertInfo {
		args = append(args, "-S")
	}
	if input.Severity != "" {
		args = append(args, "--severity", input.Severity)
	}
	if input.Parallel {
		args = append(args, "--parallel")
	}
	if input.Fast {
		args = append(args, "--fast")
	}
	if input.Sneaky {
		args = append(args, "--sneaky")
	}
	if input.IP != "" {
		if err := validateIP(input.IP); err != nil {
			return errorResult(err.Error()), nil
		}
		args = append(args, "--ip", input.IP)
	}
	if input.Warnings {
		args = append(args, "--warnings", "batch")
	}
	if input.Quiet {
		args = append(args, "--quiet")
	}
	if input.Full {
		args = append(args, "-f")
	}
	if input.OpenSSLPath != "" {
		args = append(args, "--openssl", input.OpenSSLPath)
	}

	target := input.Host
	if input.Port > 0 {
		target = fmt.Sprintf("%s:%d", input.Host, input.Port)
	}
	args = append(args, target)

	result, err := t.exec.Run(ctx, "testssl.sh", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("testssl execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## TLS/SSL Scan: %s\n\n", target)
	sb.WriteString("```\n")
	sb.WriteString(output)
	sb.WriteString("\n```\n")

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

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if len(host) > 253 {
		return fmt.Errorf("host too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(host, c) {
			return fmt.Errorf("host contains forbidden character: %q", c)
		}
	}
	return nil
}

func validateIP(ip string) error {
	if len(ip) > 45 {
		return fmt.Errorf("ip too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(ip, c) {
			return fmt.Errorf("ip contains forbidden character: %q", c)
		}
	}
	return nil
}
