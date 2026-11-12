package msf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ResourceRunTool runs an operator-authored msfconsole resource file.
type ResourceRunTool struct {
	exec executor.Executor
}

// NewResourceRun creates the resource file execution tool.
func NewResourceRun(exec executor.Executor) *ResourceRunTool {
	return &ResourceRunTool{exec: exec}
}

func (t *ResourceRunTool) Name() string { return "msf_resource_run" }

func (t *ResourceRunTool) Description() string {
	return "Run an operator-authored msfconsole resource file with msfconsole -q -r, for advanced multi-module " +
		"sequences the structured msf tools cannot express (e.g. handler plus post-exploitation chains). " +
		"The file's contents are arbitrary console commands authored by the operator: this tool trusts the " +
		"operator and does not parse or validate the file beyond its path, extension and size; never point it " +
		"at untrusted or attacker-controlled files. Approval-gated; for authorized engagements only. " +
		"Note: msfconsole startup is slow (10-60 seconds) and runtime is bounded by REDHANDS_TIMEOUT."
}

func (t *ResourceRunTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"resource_file": {
				"type": "string",
				"description": "Path to an existing operator-authored .rc resource file containing one msfconsole command per line"
			}
		},
		"required": ["resource_file"]
	}`)
}

type resourceRunInput struct {
	ResourceFile string `json:"resource_file"`
}

func (t *ResourceRunTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input resourceRunInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	if err := validateResourceFile(input.ResourceFile); err != nil {
		return errorResult(err.Error()), nil
	}

	result, err := t.exec.Run(ctx, "msfconsole", "-q", "-r", input.ResourceFile)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("msfconsole failed: %v\n%s", err, stderr)), nil
	}

	var sb strings.Builder
	sb.WriteString("## Metasploit Resource File Run\n\n")
	fmt.Fprintf(&sb, "**Resource file**: %s\n\n", input.ResourceFile)
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
