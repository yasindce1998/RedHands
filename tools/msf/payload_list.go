package msf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// payloadListKinds are the msfvenom --list reference categories.
var payloadListKinds = []string{"payloads", "encoders", "formats", "platforms", "archs"}

// PayloadListTool lists Metasploit reference data via msfvenom --list.
type PayloadListTool struct {
	exec executor.Executor
}

// NewPayloadList creates the msfvenom reference listing tool.
func NewPayloadList(exec executor.Executor) *PayloadListTool {
	return &PayloadListTool{exec: exec}
}

func (t *PayloadListTool) Name() string { return "msf_payload_list" }

func (t *PayloadListTool) Description() string {
	return "List Metasploit reference data with msfvenom --list: payloads, encoders, output formats, platforms " +
		"or architectures. Read-only lookup used to discover exact payload and encoder names for " +
		"msf_payload_generate and module names for the console tools. For authorized engagements only."
}

func (t *PayloadListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"kind": {
				"type": "string",
				"enum": ["payloads", "encoders", "formats", "platforms", "archs"],
				"description": "Reference category to list (default: payloads)"
			}
		}
	}`)
}

type payloadListInput struct {
	Kind string `json:"kind"`
}

func (t *PayloadListTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input payloadListInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	kind := input.Kind
	if kind == "" {
		kind = "payloads"
	}
	if !containsString(payloadListKinds, kind) {
		return errorResult(fmt.Sprintf("invalid kind %q: must be one of %s", kind, strings.Join(payloadListKinds, ", "))), nil
	}

	result, err := t.exec.Run(ctx, "msfvenom", "--list", kind)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("msfvenom --list %s failed: %v\n%s", kind, err, stderr)), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Metasploit %s\n\n", kind)
	sb.WriteString("```\n")
	if out := strings.TrimSpace(string(result.Stdout)); out != "" {
		sb.WriteString(out + "\n")
	} else {
		sb.WriteString("(no output)\n")
	}
	sb.WriteString("```\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
