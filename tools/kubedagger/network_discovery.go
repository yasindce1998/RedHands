package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type NetworkScanInput struct {
	Target    string `json:"target,omitempty"`
	Interface string `json:"interface,omitempty"`
	Range     int    `json:"range,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type NetworkScanTool struct {
	exec executor.Executor
}

func NewNetworkScan(exec executor.Executor) *NetworkScanTool {
	return &NetworkScanTool{exec: exec}
}

func (t *NetworkScanTool) Name() string { return "kubedagger_network_scan" }

func (t *NetworkScanTool) Description() string {
	return "Perform eBPF-powered network scanning to discover hosts and services in the cluster network. Uses XDP for high-speed packet crafting without generating typical scan signatures."
}

func (t *NetworkScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP or CIDR range to scan (e.g., '10.0.0.0/24')"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to use (e.g., 'eth0')"
			},
			"range": {
				"type": "integer",
				"description": "Port range upper bound (scans 1 to N)"
			},
			"port": {
				"type": "integer",
				"description": "Specific port to check across targets"
			}
		},
		"required": ["target"]
	}`)
}

func (t *NetworkScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetworkScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"network", "scan", "--target", input.Target}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.Range > 0 {
		args = append(args, "--range", fmt.Sprintf("%d", input.Range))
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger network scan failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Network Scan\n\n")
	if output == "" {
		sb.WriteString("No results.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

type NetworkDiscoveryInput struct {
	Target    string `json:"target,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Passive   bool   `json:"passive,omitempty"`
	Duration  int    `json:"duration,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type NetworkDiscoveryTool struct {
	exec executor.Executor
}

func NewNetworkDiscovery(exec executor.Executor) *NetworkDiscoveryTool {
	return &NetworkDiscoveryTool{exec: exec}
}

func (t *NetworkDiscoveryTool) Name() string { return "kubedagger_network_discovery" }

func (t *NetworkDiscoveryTool) Description() string {
	return "Passively discover network topology by hooking into kernel network functions with eBPF. Maps pod-to-pod communications, service endpoints, and external connections without sending any traffic."
}

func (t *NetworkDiscoveryTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP or CIDR to focus discovery on"
			},
			"mode": {
				"type": "string",
				"enum": ["passive", "active", "hybrid"],
				"description": "Discovery mode: passive (sniff only), active (probe), hybrid (both)"
			},
			"passive": {
				"type": "boolean",
				"description": "Enable passive-only mode (no packets sent)"
			},
			"duration": {
				"type": "integer",
				"description": "Duration in seconds to run discovery"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to monitor"
			}
		}
	}`)
}

func (t *NetworkDiscoveryTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetworkDiscoveryInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"network", "discover"}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.Passive {
		args = append(args, "--passive")
	}
	if input.Duration > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", input.Duration))
	}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger network discovery failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Network Discovery\n\n")
	if output == "" {
		sb.WriteString("No results.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
