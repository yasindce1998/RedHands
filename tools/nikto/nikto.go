package nikto

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type WebScanInput struct {
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
	SSL     bool   `json:"ssl,omitempty"`
	Tuning  string `json:"tuning,omitempty"`
	Plugins string `json:"plugins,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

type WebScanTool struct {
	exec *executor.BinaryExecutor
}

func NewWebScan(exec *executor.BinaryExecutor) *WebScanTool {
	return &WebScanTool{exec: exec}
}

func (t *WebScanTool) Name() string { return "nikto_scan" }

func (t *WebScanTool) Description() string {
	return "Web server scanner that checks for dangerous files, outdated software, misconfigurations, and known vulnerabilities."
}

func (t *WebScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"host": {
				"type": "string",
				"description": "Target host or URL (e.g., 'example.com' or 'https://example.com')"
			},
			"port": {
				"type": "integer",
				"description": "Target port (default: 80, or 443 with SSL)"
			},
			"ssl": {
				"type": "boolean",
				"description": "Force SSL connection"
			},
			"tuning": {
				"type": "string",
				"description": "Scan tuning options (1=interesting files, 2=misconfigs, 3=info disclosure, 4=injection, 5=remote retrieval, 6=DoS, 7=remote shell, 8=command exec, 9=SQL injection, 0=file upload)"
			},
			"plugins": {
				"type": "string",
				"description": "Specific plugins to run (comma-separated)"
			},
			"timeout": {
				"type": "integer",
				"description": "Timeout per request in seconds (default: 10)"
			}
		},
		"required": ["host"]
	}`)
}

func (t *WebScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input WebScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateHost(input.Host); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-h", input.Host, "-nointeractive", "-Format", "txt"}

	if input.Port > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", input.Port))
	}
	if input.SSL {
		args = append(args, "-ssl")
	}
	if input.Tuning != "" {
		args = append(args, "-Tuning", input.Tuning)
	}
	if input.Plugins != "" {
		args = append(args, "-Plugins", input.Plugins)
	}
	if input.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", input.Timeout))
	}

	result, err := t.exec.Run(ctx, "nikto", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("nikto execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Nikto Scan: %s\n\n", input.Host)
	fmt.Fprintf(&sb, "Found %d line(s) of output:\n\n```\n", len(lines))
	for _, line := range lines {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteString("```\n")

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

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if len(host) > 2048 {
		return fmt.Errorf("host too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(host, c) {
			return fmt.Errorf("host contains forbidden character: %q", c)
		}
	}
	return nil
}
