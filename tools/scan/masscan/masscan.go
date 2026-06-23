package masscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type MasscanInput struct {
	Targets      string `json:"targets"`
	Ports        string `json:"ports"`
	Rate         int    `json:"rate,omitempty"`
	Banners      bool   `json:"banners,omitempty"`
	TopPorts     int    `json:"top_ports,omitempty"`
	ExcludeIP    string `json:"exclude,omitempty"`
	Interface    string `json:"interface,omitempty"`
	Wait         int    `json:"wait,omitempty"`
	Retries      int    `json:"retries,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	OutputFormat string `json:"output_format,omitempty"`
	OpenOnly     bool   `json:"open_only,omitempty"`
}

type MasscanTool struct {
	exec executor.Executor
}

func NewMasscan(exec executor.Executor) *MasscanTool {
	return &MasscanTool{exec: exec}
}

func (t *MasscanTool) Name() string { return "masscan_scan" }

func (t *MasscanTool) Description() string {
	return "Internet-scale port scanner. Transmits up to 10 million packets per second. Supports banner grabbing, output format selection (JSON/XML/list), source IP binding, and retry configuration."
}

func (t *MasscanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"targets": {
				"type": "string",
				"description": "Target IP range(s) in CIDR notation (e.g., '10.0.0.0/24' or '192.168.1.1-192.168.1.254')"
			},
			"ports": {
				"type": "string",
				"description": "Port(s) to scan (e.g., '80,443', '0-65535', '1-1000')"
			},
			"rate": {
				"type": "integer",
				"description": "Packet transmit rate in packets/sec (default: 100)"
			},
			"banners": {
				"type": "boolean",
				"description": "Grab banners from discovered services"
			},
			"top_ports": {
				"type": "integer",
				"description": "Scan top N most common ports"
			},
			"exclude": {
				"type": "string",
				"description": "IP addresses/ranges to exclude from scanning"
			},
			"interface": {
				"type": "string",
				"description": "Network interface to use"
			},
			"wait": {
				"type": "integer",
				"description": "Seconds to wait for replies after transmit is done (default: 10)"
			},
			"retries": {
				"type": "integer",
				"description": "Number of retries per port (default: 0)"
			},
			"source_ip": {
				"type": "string",
				"description": "Source IP address to use (--adapter-ip)"
			},
			"output_format": {
				"type": "string",
				"enum": ["json", "xml", "list"],
				"description": "Output format: json (-oJ), xml (-oX), or list (-oL). Default: standard text"
			},
			"open_only": {
				"type": "boolean",
				"description": "Only show open ports in results"
			}
		},
		"required": ["targets", "ports"]
	}`)
}

func (t *MasscanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MasscanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTarget(input.Targets); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePorts(input.Ports); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Targets, "-p", input.Ports}

	if input.Rate > 0 {
		args = append(args, "--rate", fmt.Sprintf("%d", input.Rate))
	}
	if input.Banners {
		args = append(args, "--banners")
	}
	if input.TopPorts > 0 {
		args = append(args, "--top-ports", fmt.Sprintf("%d", input.TopPorts))
	}
	if input.ExcludeIP != "" {
		args = append(args, "--exclude", input.ExcludeIP)
	}
	if input.Interface != "" {
		args = append(args, "-e", input.Interface)
	}
	if input.Wait > 0 {
		args = append(args, "--wait", fmt.Sprintf("%d", input.Wait))
	}
	if input.Retries > 0 {
		args = append(args, "--retries", fmt.Sprintf("%d", input.Retries))
	}
	if input.SourceIP != "" {
		if err := validateIP(input.SourceIP); err != nil {
			return errorResult(err.Error()), nil
		}
		args = append(args, "--adapter-ip", input.SourceIP)
	}
	switch input.OutputFormat {
	case "json":
		args = append(args, "-oJ", "-")
	case "xml":
		args = append(args, "-oX", "-")
	case "list":
		args = append(args, "-oL", "-")
	}
	if input.OpenOnly {
		args = append(args, "--open-only")
	}

	result, err := t.exec.Run(ctx, "masscan", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("masscan execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Masscan Results: %s\n\n", input.Targets)
	fmt.Fprintf(&sb, "Ports: %s | Found %d result(s):\n\n", input.Ports, countResults(lines))
	sb.WriteString("```\n")
	sb.WriteString(output)
	sb.WriteString("\n```\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

func countResults(lines []string) int {
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Discovered") || strings.Contains(line, "open") {
			count++
		}
	}
	return count
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("targets is required")
	}
	if len(target) > 2048 {
		return fmt.Errorf("targets too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(target, c) {
			return fmt.Errorf("targets contains forbidden character: %q", c)
		}
	}
	return nil
}

func validatePorts(ports string) error {
	if ports == "" {
		return fmt.Errorf("ports is required")
	}
	if len(ports) > 1024 {
		return fmt.Errorf("ports specification too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(ports, c) {
			return fmt.Errorf("ports contains forbidden character: %q", c)
		}
	}
	return nil
}

func validateIP(ip string) error {
	if len(ip) > 45 {
		return fmt.Errorf("source_ip too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(ip, c) {
			return fmt.Errorf("source_ip contains forbidden character: %q", c)
		}
	}
	return nil
}
