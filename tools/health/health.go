package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

var version = "0.2.0"

type HealthCheckTool struct {
	binaries []string
}

func NewHealthCheck(binaries []string) *HealthCheckTool {
	return &HealthCheckTool{binaries: binaries}
}

func (t *HealthCheckTool) Name() string { return "redhands_health" }

func (t *HealthCheckTool) Description() string {
	return "Check the health and status of the RedHands MCP server, including available tools and binary dependencies."
}

func (t *HealthCheckTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`)
}

func (t *HealthCheckTool) Execute(_ context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	var sb strings.Builder

	sb.WriteString("## RedHands Health Check\n\n")
	fmt.Fprintf(&sb, "**Version:** %s\n", version)
	fmt.Fprintf(&sb, "**Platform:** %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&sb, "**Go Version:** %s\n\n", runtime.Version())

	sb.WriteString("### Binary Dependencies\n\n")
	sb.WriteString("| Binary | Status | Path |\n")
	sb.WriteString("|--------|--------|------|\n")

	for _, bin := range t.binaries {
		path, err := exec.LookPath(bin)
		if err != nil {
			fmt.Fprintf(&sb, "| %s | not found | - |\n", bin)
		} else {
			fmt.Fprintf(&sb, "| %s | available | %s |\n", bin, path)
		}
	}

	sb.WriteString("\n### Status: OK\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
