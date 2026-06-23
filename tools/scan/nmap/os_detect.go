package nmap

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	nmapparser "github.com/yasindce1998/redhands/pkg/nmap"
)

type OSDetectInput struct {
	Target string `json:"target"`
}

type OSDetectTool struct {
	exec executor.Executor
}

func NewOSDetect(exec executor.Executor) *OSDetectTool {
	return &OSDetectTool{exec: exec}
}

func (t *OSDetectTool) Name() string { return "nmap_os_detect" }

func (t *OSDetectTool) Description() string {
	return "Detect the operating system of target hosts using Nmap's TCP/IP fingerprinting. Requires root/admin privileges."
}

func (t *OSDetectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP address or hostname for OS detection"
			}
		},
		"required": ["target"]
	}`)
}

func (t *OSDetectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input OSDetectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := ValidateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-oX", "-", "-O", input.Target}

	result, err := t.exec.Run(ctx, "nmap", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("nmap execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	run, err := nmapparser.ParseBytes(result.Stdout)
	if err != nil {
		return errorResult("failed to parse nmap output: " + err.Error()), nil
	}

	summary := nmapparser.Summary(run)
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: summary}},
	}, nil
}
