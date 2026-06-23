package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	nmapparser "github.com/yasindce1998/redhands/pkg/nmap"
)

type VulnScanInput struct {
	Target  string `json:"target"`
	Scripts string `json:"scripts,omitempty"`
	Ports   string `json:"ports,omitempty"`
}

type VulnScanTool struct {
	exec executor.Executor
}

func NewVulnScan(exec executor.Executor) *VulnScanTool {
	return &VulnScanTool{exec: exec}
}

func (t *VulnScanTool) Name() string { return "nmap_vuln_scan" }

func (t *VulnScanTool) Description() string {
	return "Run Nmap NSE vulnerability scanning scripts against target hosts. Identifies known vulnerabilities in discovered services."
}

func (t *VulnScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP address, CIDR range, or hostname to scan"
			},
			"scripts": {
				"type": "string",
				"description": "NSE script category or specific scripts (default: 'vuln'). Examples: 'vuln', 'vulners', 'http-vuln-*'"
			},
			"ports": {
				"type": "string",
				"description": "Port specification (e.g., '80', '1-1024', '80,443,8080')"
			}
		},
		"required": ["target"]
	}`)
}

var allowedScriptPrefixes = []string{
	"vuln", "http-vuln", "ssl-", "smb-vuln", "ftp-vuln", "vulners",
	"smtp-vuln", "rdp-vuln", "ms-sql-", "mysql-vuln",
}

func validateScripts(scripts string) error {
	if scripts == "" {
		return nil
	}
	for _, meta := range shellMetachars {
		if strings.Contains(scripts, meta) {
			return fmt.Errorf("script name contains forbidden character: %q", meta)
		}
	}
	parts := strings.Split(scripts, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		allowed := false
		for _, prefix := range allowedScriptPrefixes {
			if strings.HasPrefix(part, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("script %q is not in the allowed list", part)
		}
	}
	return nil
}

func (t *VulnScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input VulnScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := ValidateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := ValidatePorts(input.Ports); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := validateScripts(input.Scripts); err != nil {
		return errorResult(err.Error()), nil
	}

	scripts := input.Scripts
	if scripts == "" {
		scripts = "vuln"
	}

	args := []string{"-oX", "-", "-sV", "--script", scripts}

	if input.Ports != "" {
		args = append(args, "-p", input.Ports)
	}

	args = append(args, input.Target)

	result, err := t.exec.Run(ctx, "nmap", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("nmap execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	run, err := nmapparser.ParseBytes(result.Stdout)
	if err != nil {
		return errorResult("failed to parse nmap output: " + err.Error()), nil
	}

	summary := nmapparser.Summary(run)
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: summary}},
	}, nil
}
