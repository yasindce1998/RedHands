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
	Target          string `json:"target"`
	Templates       string `json:"templates,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Tags            string `json:"tags,omitempty"`
	ExcTags         string `json:"exclude_tags,omitempty"`
	RateLimit       int    `json:"rate_limit,omitempty"`
	BulkSize        int    `json:"bulk_size,omitempty"`
	Proxy           string `json:"proxy,omitempty"`
	InteractshSrv   string `json:"interactsh_server,omitempty"`
	Headless        bool   `json:"headless,omitempty"`
	SystemResolvers bool   `json:"system_resolvers,omitempty"`
	NewTemplates    bool   `json:"new_templates,omitempty"`
	AutomaticScan   bool   `json:"automatic_scan,omitempty"`
	TemplateID      string `json:"template_id,omitempty"`
	ExcludeID       string `json:"exclude_id,omitempty"`
	Author          string `json:"author,omitempty"`
	Type            string `json:"type,omitempty"`
	Concurrency     int    `json:"concurrency,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`
}

type NucleiScanTool struct {
	exec executor.Executor
}

func NewNucleiScan(exec executor.Executor) *NucleiScanTool {
	return &NucleiScanTool{exec: exec}
}

func (t *NucleiScanTool) Name() string { return "nuclei_scan" }

func (t *NucleiScanTool) Description() string {
	return "Run template-based vulnerability scanning with Nuclei. Supports severity filtering, tag-based selection, rate limiting, headless browser scanning, and interactsh-based OOB detection."
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
			},
			"proxy": {
				"type": "string",
				"description": "HTTP/SOCKS5 proxy URL (e.g., 'http://127.0.0.1:8080')"
			},
			"interactsh_server": {
				"type": "string",
				"description": "Custom interactsh server URL for OOB testing"
			},
			"headless": {
				"type": "boolean",
				"description": "Enable headless browser-based templates"
			},
			"system_resolvers": {
				"type": "boolean",
				"description": "Use system DNS resolvers instead of built-in"
			},
			"new_templates": {
				"type": "boolean",
				"description": "Run only newly added templates"
			},
			"automatic_scan": {
				"type": "boolean",
				"description": "Automatic web scan using wappalyzer technology detection"
			},
			"template_id": {
				"type": "string",
				"description": "Run specific template IDs (comma-separated, e.g., 'CVE-2021-44228')"
			},
			"exclude_id": {
				"type": "string",
				"description": "Exclude specific template IDs (comma-separated)"
			},
			"author": {
				"type": "string",
				"description": "Filter templates by author (comma-separated)"
			},
			"type": {
				"type": "string",
				"enum": ["http", "dns", "file", "network", "headless", "ssl"],
				"description": "Filter templates by protocol type"
			},
			"concurrency": {
				"type": "integer",
				"description": "Maximum number of templates to execute in parallel (default: 25)"
			},
			"timeout": {
				"type": "integer",
				"description": "Timeout in seconds for each request (default: 10)"
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
	if input.Proxy != "" {
		args = append(args, "-proxy", input.Proxy)
	}
	if input.InteractshSrv != "" {
		args = append(args, "-iserver", input.InteractshSrv)
	}
	if input.Headless {
		args = append(args, "-headless")
	}
	if input.SystemResolvers {
		args = append(args, "-sr")
	}
	if input.NewTemplates {
		args = append(args, "-nt")
	}
	if input.AutomaticScan {
		args = append(args, "-as")
	}
	if input.TemplateID != "" {
		args = append(args, "-id", input.TemplateID)
	}
	if input.ExcludeID != "" {
		args = append(args, "-eid", input.ExcludeID)
	}
	if input.Author != "" {
		args = append(args, "-author", input.Author)
	}
	if input.Type != "" {
		args = append(args, "-type", input.Type)
	}
	if input.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", input.Concurrency))
	}
	if input.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", input.Timeout))
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
