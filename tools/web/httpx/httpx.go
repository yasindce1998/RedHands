package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type HTTPProbeInput struct {
	Targets    string `json:"targets"`
	Ports      string `json:"ports,omitempty"`
	StatusCode bool   `json:"status_code,omitempty"`
	Title      bool   `json:"title,omitempty"`
	TechDetect bool   `json:"tech_detect,omitempty"`
	FollowRedir bool  `json:"follow_redirects,omitempty"`
	Threads    int    `json:"threads,omitempty"`
}

type HTTPProbeTool struct {
	exec *executor.BinaryExecutor
}

func NewHTTPProbe(exec *executor.BinaryExecutor) *HTTPProbeTool {
	return &HTTPProbeTool{exec: exec}
}

func (t *HTTPProbeTool) Name() string { return "httpx_probe" }

func (t *HTTPProbeTool) Description() string {
	return "Probe HTTP services on targets to detect live web servers, extract titles, status codes, and technologies."
}

func (t *HTTPProbeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"targets": {
				"type": "string",
				"description": "Comma-separated list of targets (IPs, domains, or URLs) to probe"
			},
			"ports": {
				"type": "string",
				"description": "Ports to probe (e.g., '80,443,8080,8443')"
			},
			"status_code": {
				"type": "boolean",
				"description": "Include HTTP status code in output"
			},
			"title": {
				"type": "boolean",
				"description": "Include page title in output"
			},
			"tech_detect": {
				"type": "boolean",
				"description": "Enable technology detection (Wappalyzer-like)"
			},
			"follow_redirects": {
				"type": "boolean",
				"description": "Follow HTTP redirects"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 50)"
			}
		},
		"required": ["targets"]
	}`)
}

func (t *HTTPProbeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HTTPProbeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTargets(input.Targets); err != nil {
		return errorResult(err.Error()), nil
	}

	targets := strings.Split(input.Targets, ",")
	args := []string{"-silent"}

	if input.Ports != "" {
		args = append(args, "-ports", input.Ports)
	}
	if input.StatusCode {
		args = append(args, "-status-code")
	}
	if input.Title {
		args = append(args, "-title")
	}
	if input.TechDetect {
		args = append(args, "-tech-detect")
	}
	if input.FollowRedir {
		args = append(args, "-follow-redirects")
	}
	if input.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", input.Threads))
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target != "" {
			args = append(args, "-u", target)
		}
	}

	result, err := t.exec.Run(ctx, "httpx", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("httpx execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "## HTTP Probe Results\n\nProbed %d target(s), %d responded:\n\n", len(targets), len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Fprintf(&sb, "- %s\n", line)
		}
	}

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

func validateTargets(targets string) error {
	if targets == "" {
		return fmt.Errorf("targets is required")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(targets, c) {
			return fmt.Errorf("targets contains forbidden character: %q", c)
		}
	}
	return nil
}
