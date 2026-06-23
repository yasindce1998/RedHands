package rustscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type RustScanInput struct {
	Target    string `json:"target"`
	Ports     string `json:"ports,omitempty"`
	Range     string `json:"range,omitempty"`
	BatchSize int    `json:"batch_size,omitempty"`
	Timeout   int    `json:"timeout,omitempty"`
	Tries     int    `json:"tries,omitempty"`
	TopPorts  bool   `json:"top_ports,omitempty"`
	Greppable bool   `json:"greppable,omitempty"`
	Ulimit    int    `json:"ulimit,omitempty"`
}

type RustScanTool struct {
	exec *executor.BinaryExecutor
}

func NewRustScan(exec *executor.BinaryExecutor) *RustScanTool {
	return &RustScanTool{exec: exec}
}

func (t *RustScanTool) Name() string { return "rustscan_scan" }

func (t *RustScanTool) Description() string {
	return "Modern port scanner. Scans all 65535 ports in 3 seconds with adaptive timing. Automatically pipes open ports to Nmap for service detection."
}

func (t *RustScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP or hostname to scan"
			},
			"ports": {
				"type": "string",
				"description": "Specific ports to scan (e.g., '80,443,8080')"
			},
			"range": {
				"type": "string",
				"description": "Port range to scan (e.g., '1-65535')"
			},
			"batch_size": {
				"type": "integer",
				"description": "Number of ports to scan at once (default: 4500)"
			},
			"timeout": {
				"type": "integer",
				"description": "Timeout in milliseconds for each port (default: 1500)"
			},
			"tries": {
				"type": "integer",
				"description": "Number of tries per port (default: 1)"
			},
			"top_ports": {
				"type": "boolean",
				"description": "Scan top 1000 ports only"
			},
			"greppable": {
				"type": "boolean",
				"description": "Output in greppable format"
			},
			"ulimit": {
				"type": "integer",
				"description": "Set the file descriptor limit (ulimit)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *RustScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RustScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-a", input.Target}

	if input.Ports != "" {
		args = append(args, "-p", input.Ports)
	}
	if input.Range != "" {
		args = append(args, "--range", input.Range)
	}
	if input.BatchSize > 0 {
		args = append(args, "-b", fmt.Sprintf("%d", input.BatchSize))
	}
	if input.Timeout > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", input.Timeout))
	}
	if input.Tries > 0 {
		args = append(args, "--tries", fmt.Sprintf("%d", input.Tries))
	}
	if input.TopPorts {
		args = append(args, "--top")
	}
	if input.Greppable {
		args = append(args, "-g")
	}
	if input.Ulimit > 0 {
		args = append(args, "--ulimit", fmt.Sprintf("%d", input.Ulimit))
	}

	result, err := t.exec.Run(ctx, "rustscan", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("rustscan execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## RustScan Results: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("No open ports found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

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

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > 253 {
		return fmt.Errorf("target too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(target, c) {
			return fmt.Errorf("target contains forbidden character: %q", c)
		}
	}
	return nil
}
