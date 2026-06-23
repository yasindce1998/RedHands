package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type NucleiScanInput struct {
	Target    string `json:"target"`
	Templates string `json:"templates,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Tags      string `json:"tags,omitempty"`
	ExcTags   string `json:"exclude_tags,omitempty"`
	RateLimit int    `json:"rate_limit,omitempty"`
	BulkSize  int    `json:"bulk_size,omitempty"`
}

type NucleiScanTool struct {
	exec *executor.BinaryExecutor
}

func NewNucleiScan(exec *executor.BinaryExecutor) *NucleiScanTool {
	return &NucleiScanTool{exec: exec}
}

func (t *NucleiScanTool) Name() string { return "nuclei_scan" }

func (t *NucleiScanTool) Description() string {
	return "Run template-based vulnerability scanning with Nuclei. Supports severity filtering, tag-based selection, and rate limiting."
}

func (t *NucleiScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target URL or host to scan (e.g., 'https://example.com')"
			},
			"templates": {
				"type": "string",
				"description": "Specific template or template directory to use"
			},
			"severity": {
				"type": "string",
				"description": "Filter by severity: info, low, medium, high, critical (comma-separated)"
			},
			"tags": {
				"type": "string",
				"description": "Filter templates by tags (e.g., 'cve,oast,sqli')"
			},
			"exclude_tags": {
				"type": "string",
				"description": "Exclude templates by tags (e.g., 'dos,fuzz')"
			},
			"rate_limit": {
				"type": "integer",
				"description": "Maximum requests per second (default: 150)"
			},
			"bulk_size": {
				"type": "integer",
				"description": "Number of templates to run in parallel (default: 25)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *NucleiScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input NucleiScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.Target, "-silent", "-nc"}

	if input.Templates != "" {
		args = append(args, "-t", input.Templates)
	}
	if input.Severity != "" {
		args = append(args, "-severity", input.Severity)
	}
	if input.Tags != "" {
		args = append(args, "-tags", input.Tags)
	}
	if input.ExcTags != "" {
		args = append(args, "-exclude-tags", input.ExcTags)
	}
	if input.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", input.RateLimit))
	}
	if input.BulkSize > 0 {
		args = append(args, "-bulk-size", fmt.Sprintf("%d", input.BulkSize))
	}

	result, err := t.exec.Run(ctx, "nuclei", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("nuclei execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: fmt.Sprintf("## Nuclei Scan: %s\n\nNo vulnerabilities found.", input.Target)}},
		}, nil
	}

	lines := strings.Split(output, "\n")
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Nuclei Scan: %s\n\nFound %d issue(s):\n\n", input.Target, len(lines))
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

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > 2048 {
		return fmt.Errorf("target too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(target, c) {
			return fmt.Errorf("target contains forbidden character: %q", c)
		}
	}
	return nil
}
