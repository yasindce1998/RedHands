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
	IP    string `json:"ip"`
	Port  string `json:"port"`
	Range string `json:"range,omitempty"`
}

type NetworkScanTool struct {
	exec executor.Executor
}

func NewNetworkScan(exec executor.Executor) *NetworkScanTool {
	return &NetworkScanTool{exec: exec}
}

func (t *NetworkScanTool) Name() string { return "kubedagger_network_scan" }

func (t *NetworkScanTool) Description() string {
	return "Actively scan a target IPv4 address and port range to discover open services in the cluster network. Probes the given port (or a range of ports around it) and reports which are open."
}

func (t *NetworkScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"ip": {
				"type": "string",
				"description": "Target IPv4 address to scan, e.g. '10.0.0.1' (required)"
			},
			"port": {
				"type": "string",
				"description": "Port to scan, e.g. '80' (required, max 5 chars)"
			},
			"range": {
				"type": "string",
				"description": "Number of ports to scan around the target port (default: 20)"
			}
		},
		"required": ["ip", "port"]
	}`)
}

func (t *NetworkScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetworkScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.IP == "" {
		return errorResult("ip is required"), nil
	}
	if input.Port == "" {
		return errorResult("port is required"), nil
	}
	if err := validateSafeString(input.IP, "ip"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateIPv4(input.IP); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Port, "port"); err != nil {
		return errorResult(err.Error()), nil
	}
	if len(input.Port) > 5 {
		return errorResult("port too long (max 5 chars)"), nil
	}
	if err := validateSafeString(input.Range, "range"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"network_discovery", "scan", "--ip", input.IP, "--port", input.Port}
	if input.Range != "" {
		args = append(args, "--range", input.Range)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger network_discovery scan failed: %s\n%s", err.Error(), stderr)), nil
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
	Active  bool `json:"active,omitempty"`
	Passive bool `json:"passive,omitempty"`
}

type NetworkDiscoveryTool struct {
	exec executor.Executor
}

func NewNetworkDiscovery(exec executor.Executor) *NetworkDiscoveryTool {
	return &NetworkDiscoveryTool{exec: exec}
}

func (t *NetworkDiscoveryTool) Name() string { return "kubedagger_network_discovery" }

func (t *NetworkDiscoveryTool) Description() string {
	return "Discover the current network topology as plain text. Passive mode maps known connections without sending traffic; active mode probes to enrich the map with responsive hosts and services."
}

func (t *NetworkDiscoveryTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"active": {
				"type": "boolean",
				"description": "Run active probing in addition to the cached view"
			},
			"passive": {
				"type": "boolean",
				"description": "Restrict discovery to passive observation (no packets sent)"
			}
		}
	}`)
}

func (t *NetworkDiscoveryTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NetworkDiscoveryInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"network_discovery", "get"}
	if input.Active {
		args = append(args, "--active")
	}
	if input.Passive {
		args = append(args, "--passive")
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger network_discovery get failed: %s\n%s", err.Error(), stderr)), nil
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
