package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// InfoTool wraps `barzakh-scanner info` (verified against scanner main.rs):
//
//	info
//
// The subcommand takes no flags at all; cmd_info() prints scanner version
// (CARGO_PKG_VERSION), the detector count, supported architectures, report
// formats and the detector category overview. It is a pure read-only query;
// the scanner main() exits 2 on error, so no detection-exit handling applies.
type InfoTool struct {
	exec executor.Executor
}

func NewInfo(exec executor.Executor) *InfoTool {
	return &InfoTool{exec: exec}
}

func (t *InfoTool) Name() string { return "barzakh_info" }

func (t *InfoTool) Description() string {
	return "Show Barzakh scanner platform information and statistics: scanner version, number of loaded security detectors, supported architectures, available report formats, and the detector category overview (TPM/PCR, memory forensics, firmware structure, Secure Boot, Intel ME/Ring-3, Ring-4/microarch). Read-only query with no parameters."
}

func (t *InfoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {},
		"required": []
	}`)
}

func (t *InfoTool) Execute(ctx context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	result, err := t.exec.Run(ctx, "barzakh-scanner", "info")
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("barzakh-scanner info failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Barzakh Scanner Info\n\n")
	if output == "" {
		sb.WriteString("Scanner info command completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
