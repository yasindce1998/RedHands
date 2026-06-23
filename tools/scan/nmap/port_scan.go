package nmap

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	nmapparser "github.com/yasindce1998/redhands/pkg/nmap"
)

type PortScanInput struct {
	Target   string `json:"target"`
	Ports    string `json:"ports,omitempty"`
	ScanType string `json:"scan_type,omitempty"`
	TopPorts int    `json:"top_ports,omitempty"`
}

type PortScanTool struct {
	exec *executor.BinaryExecutor
}

func NewPortScan(exec *executor.BinaryExecutor) *PortScanTool {
	return &PortScanTool{exec: exec}
}

func (t *PortScanTool) Name() string { return "nmap_port_scan" }

func (t *PortScanTool) Description() string {
	return "Scan target hosts for open ports using Nmap. Supports TCP SYN, TCP Connect, and UDP scans."
}

func (t *PortScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP address, CIDR range, or hostname to scan"
			},
			"ports": {
				"type": "string",
				"description": "Port specification (e.g., '80', '1-1024', '80,443,8080', 'T:80,U:53')"
			},
			"scan_type": {
				"type": "string",
				"enum": ["syn", "connect", "udp"],
				"description": "Scan type: syn (default, requires root), connect (no root needed), udp"
			},
			"top_ports": {
				"type": "integer",
				"description": "Scan the N most common ports instead of specifying ports"
			}
		},
		"required": ["target"]
	}`)
}

func (t *PortScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PortScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := ValidateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := ValidatePorts(input.Ports); err != nil {
		return errorResult(err.Error()), nil
	}

	args := buildPortScanArgs(input)
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

func buildPortScanArgs(input PortScanInput) []string {
	args := []string{"-oX", "-"}

	switch input.ScanType {
	case "syn":
		args = append(args, "-sS")
	case "connect":
		args = append(args, "-sT")
	case "udp":
		args = append(args, "-sU")
	default:
		args = append(args, "-sS")
	}

	if input.TopPorts > 0 {
		args = append(args, "--top-ports", fmt.Sprintf("%d", input.TopPorts))
	} else if input.Ports != "" {
		args = append(args, "-p", input.Ports)
	}

	args = append(args, input.Target)
	return args
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

