package tshark

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ExtractInput struct {
	File   string `json:"file"`
	Fields string `json:"fields"`
	Filter string `json:"filter,omitempty"`
}

type ExtractTool struct {
	exec executor.Executor
}

func NewExtract(exec executor.Executor) *ExtractTool {
	return &ExtractTool{exec: exec}
}

func (t *ExtractTool) Name() string { return "tshark_extract" }

func (t *ExtractTool) Description() string {
	return "Extract specific protocol fields from packets in a pcap file. Output is tab-separated values suitable for further processing."
}

func (t *ExtractTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"file": {
				"type": "string",
				"description": "Path to pcap/pcapng file"
			},
			"fields": {
				"type": "string",
				"description": "Comma-separated field names (e.g., ip.src,ip.dst,http.host,dns.qry.name)"
			},
			"filter": {
				"type": "string",
				"description": "Display filter"
			}
		},
		"required": ["file", "fields"]
	}`)
}

func (t *ExtractTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ExtractInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.File, "file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateRequired(input.Fields, "fields"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Filter, "filter"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-r", input.File, "-T", "fields"}
	for _, f := range strings.Split(input.Fields, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			args = append(args, "-e", f)
		}
	}
	if input.Filter != "" {
		args = append(args, "-Y", input.Filter)
	}

	result, err := t.exec.Run(ctx, "tshark", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("tshark extract failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## tshark Field Extraction\n\n")
	fmt.Fprintf(&sb, "**Fields**: %s\n\n", input.Fields)
	if output == "" {
		sb.WriteString("No data extracted.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
