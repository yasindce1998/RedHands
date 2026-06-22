package nmap

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redhands-sec/redhands/pkg/executor"
	"github.com/redhands-sec/redhands/pkg/mcp"
	nmapparser "github.com/redhands-sec/redhands/pkg/nmap"
)

type ServiceDetectInput struct {
	Target    string `json:"target"`
	Ports     string `json:"ports,omitempty"`
	Intensity int    `json:"intensity,omitempty"`
}

type ServiceDetectTool struct {
	exec *executor.BinaryExecutor
}

func NewServiceDetect(exec *executor.BinaryExecutor) *ServiceDetectTool {
	return &ServiceDetectTool{exec: exec}
}

func (t *ServiceDetectTool) Name() string { return "nmap_service_detect" }

func (t *ServiceDetectTool) Description() string {
	return "Detect service versions running on open ports using Nmap's service/version detection probes."
}

func (t *ServiceDetectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target IP address, CIDR range, or hostname to scan"
			},
			"ports": {
				"type": "string",
				"description": "Port specification (e.g., '80', '1-1024', '80,443,8080')"
			},
			"intensity": {
				"type": "integer",
				"minimum": 0,
				"maximum": 9,
				"description": "Version detection intensity (0-9, default 7). Higher is more thorough but slower."
			}
		},
		"required": ["target"]
	}`)
}

func (t *ServiceDetectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ServiceDetectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := ValidateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := ValidatePorts(input.Ports); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-oX", "-", "-sV"}

	if input.Intensity > 0 {
		args = append(args, "--version-intensity", fmt.Sprintf("%d", input.Intensity))
	}

	if input.Ports != "" {
		args = append(args, "-p", input.Ports)
	}

	args = append(args, input.Target)

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
