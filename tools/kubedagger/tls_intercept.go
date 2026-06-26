package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type TLSInterceptInput struct {
	Target   string `json:"target,omitempty"`
	Port     int    `json:"port,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Duration int    `json:"duration,omitempty"`
	Output   string `json:"output,omitempty"`
}

type TLSInterceptTool struct {
	exec executor.Executor
}

func NewTLSIntercept(exec executor.Executor) *TLSInterceptTool {
	return &TLSInterceptTool{exec: exec}
}

func (t *TLSInterceptTool) Name() string { return "kubedagger_tls_intercept" }

func (t *TLSInterceptTool) Description() string {
	return "Intercept TLS-encrypted traffic by hooking OpenSSL/BoringSSL/GnuTLS read/write functions with eBPF uprobes. Captures plaintext data before encryption or after decryption without needing certificates or MITM proxy."
}

func (t *TLSInterceptTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target process name or pod to intercept"
			},
			"port": {
				"type": "integer",
				"description": "Filter by destination port"
			},
			"pid": {
				"type": "integer",
				"description": "Target process ID"
			},
			"duration": {
				"type": "integer",
				"description": "Capture duration in seconds"
			},
			"output": {
				"type": "string",
				"enum": ["text", "hex", "pcap"],
				"description": "Output format"
			}
		}
	}`)
}

func (t *TLSInterceptTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TLSInterceptInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"tls-intercept"}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Duration > 0 {
		args = append(args, "--duration", fmt.Sprintf("%d", input.Duration))
	}
	if input.Output != "" {
		args = append(args, "--output", input.Output)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger tls-intercept failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger TLS Intercept\n\n")
	if output == "" {
		sb.WriteString("No traffic captured.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
