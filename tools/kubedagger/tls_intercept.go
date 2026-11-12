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
	Action string `json:"action,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Lib    string `json:"lib,omitempty"`
}

type TLSInterceptTool struct {
	exec executor.Executor
}

func NewTLSIntercept(exec executor.Executor) *TLSInterceptTool {
	return &TLSInterceptTool{exec: exec}
}

func (t *TLSInterceptTool) Name() string { return "kubedagger_tls_intercept" }

func (t *TLSInterceptTool) Description() string {
	return "Intercept TLS-encrypted traffic by hooking OpenSSL or GnuTLS read/write functions with eBPF uprobes. Attach to a process, dump captured plaintext, or detach, all without needing certificates or a MITM proxy."
}

func (t *TLSInterceptTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["attach", "dump", "detach"],
				"description": "Intercept action (default: attach)"
			},
			"pid": {
				"type": "integer",
				"description": "Target process ID to hook"
			},
			"lib": {
				"type": "string",
				"enum": ["openssl", "gnutls"],
				"description": "TLS library used by the target process (default: openssl)"
			}
		}
	}`)
}

func (t *TLSInterceptTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TLSInterceptInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"tls-intercept"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.PID > 0 {
		args = append(args, "--pid", fmt.Sprintf("%d", input.PID))
	}
	if input.Lib != "" {
		args = append(args, "--lib", input.Lib)
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
