package feroxbuster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FeroxInput struct {
	URL          string `json:"url"`
	Wordlist     string `json:"wordlist,omitempty"`
	Threads      int    `json:"threads,omitempty"`
	Depth        int    `json:"depth,omitempty"`
	StatusCodes  string `json:"status_codes,omitempty"`
	FilterStatus string `json:"filter_status,omitempty"`
	FilterSize   string `json:"filter_size,omitempty"`
	FilterWords  string `json:"filter_words,omitempty"`
	Extensions   string `json:"extensions,omitempty"`
	Headers      string `json:"headers,omitempty"`
	NoRecursion  bool   `json:"no_recursion,omitempty"`
	Timeout      int    `json:"timeout,omitempty"`
	Proxy        string `json:"proxy,omitempty"`
	Insecure     bool   `json:"insecure,omitempty"`
	ExtractLinks bool   `json:"extract_links,omitempty"`
	Methods      string `json:"methods,omitempty"`
	RandomAgent  bool   `json:"random_agent,omitempty"`
	RateLimit    int    `json:"rate_limit,omitempty"`
	FilterLines  string `json:"filter_lines,omitempty"`
	AutoTune     bool   `json:"auto_tune,omitempty"`
	AutoBail     bool   `json:"auto_bail,omitempty"`
	TimeLimit    string `json:"time_limit,omitempty"`
	DontFilter   bool   `json:"dont_filter,omitempty"`
	JSON         bool   `json:"json,omitempty"`
}

type FeroxTool struct {
	exec executor.Executor
}

func NewFeroxbuster(exec executor.Executor) *FeroxTool {
	return &FeroxTool{exec: exec}
}

func (t *FeroxTool) Name() string { return "feroxbuster_scan" }

func (t *FeroxTool) Description() string {
	return "Fast, recursive content discovery tool written in Rust. Performs forced browsing to find hidden files and directories with advanced filtering, auto-calibration, auto-bail, rate limiting, and link extraction."
}

func (t *FeroxTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL to scan (e.g., 'https://example.com')"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to wordlist (default: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt)"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 50)"
			},
			"depth": {
				"type": "integer",
				"description": "Maximum recursion depth (default: 4)"
			},
			"status_codes": {
				"type": "string",
				"description": "Comma-separated status codes to include (e.g., '200,301,302,403')"
			},
			"filter_status": {
				"type": "string",
				"description": "Comma-separated status codes to filter/exclude"
			},
			"filter_size": {
				"type": "string",
				"description": "Filter responses by size (e.g., '0' to filter empty)"
			},
			"filter_words": {
				"type": "string",
				"description": "Filter responses by word count"
			},
			"extensions": {
				"type": "string",
				"description": "File extensions to search (e.g., 'php,html,js,txt')"
			},
			"headers": {
				"type": "string",
				"description": "Custom headers (semicolon-separated, e.g., 'X-Token: abc;Auth: Bearer xyz')"
			},
			"no_recursion": {
				"type": "boolean",
				"description": "Disable recursion"
			},
			"timeout": {
				"type": "integer",
				"description": "Request timeout in seconds (default: 7)"
			},
			"proxy": {
				"type": "string",
				"description": "Proxy URL (e.g., 'http://127.0.0.1:8080')"
			},
			"insecure": {
				"type": "boolean",
				"description": "Disable TLS certificate validation"
			},
			"extract_links": {
				"type": "boolean",
				"description": "Extract links from response bodies"
			},
			"methods": {
				"type": "string",
				"description": "HTTP methods to use (comma-separated, default: GET)"
			},
			"random_agent": {
				"type": "boolean",
				"description": "Use a random User-Agent for each request"
			},
			"rate_limit": {
				"type": "integer",
				"description": "Limit requests per second"
			},
			"filter_lines": {
				"type": "string",
				"description": "Filter responses by line count"
			},
			"auto_tune": {
				"type": "boolean",
				"description": "Automatically lower scan speed to reduce errors"
			},
			"auto_bail": {
				"type": "boolean",
				"description": "Automatically stop scanning when too many errors are encountered"
			},
			"time_limit": {
				"type": "string",
				"description": "Maximum scan time (e.g., '10m', '1h', '30s')"
			},
			"dont_filter": {
				"type": "boolean",
				"description": "Disable all default auto-filtering"
			},
			"json": {
				"type": "boolean",
				"description": "Output results in JSON format"
			}
		},
		"required": ["url"]
	}`)
}

func (t *FeroxTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FeroxInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.URL, "--no-state", "-q"}

	if input.Wordlist != "" {
		args = append(args, "-w", input.Wordlist)
	}
	if input.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", input.Threads))
	}
	if input.Depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", input.Depth))
	}
	if input.StatusCodes != "" {
		args = append(args, "-s", input.StatusCodes)
	}
	if input.FilterStatus != "" {
		args = append(args, "-C", input.FilterStatus)
	}
	if input.FilterSize != "" {
		args = append(args, "-S", input.FilterSize)
	}
	if input.FilterWords != "" {
		args = append(args, "-W", input.FilterWords)
	}
	if input.Extensions != "" {
		args = append(args, "-x", input.Extensions)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, ";") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "-H", h)
			}
		}
	}
	if input.NoRecursion {
		args = append(args, "-n")
	}
	if input.Timeout > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", input.Timeout))
	}
	if input.Proxy != "" {
		args = append(args, "-p", input.Proxy)
	}
	if input.Insecure {
		args = append(args, "-k")
	}
	if input.ExtractLinks {
		args = append(args, "-e")
	}
	if input.Methods != "" {
		for m := range strings.SplitSeq(input.Methods, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				args = append(args, "-m", m)
			}
		}
	}
	if input.RandomAgent {
		args = append(args, "--random-agent")
	}
	if input.RateLimit > 0 {
		args = append(args, "-L", fmt.Sprintf("%d", input.RateLimit))
	}
	if input.FilterLines != "" {
		args = append(args, "-N", input.FilterLines)
	}
	if input.AutoTune {
		args = append(args, "--auto-tune")
	}
	if input.AutoBail {
		args = append(args, "--auto-bail")
	}
	if input.TimeLimit != "" {
		args = append(args, "--time-limit", input.TimeLimit)
	}
	if input.DontFilter {
		args = append(args, "--dont-filter")
	}
	if input.JSON {
		args = append(args, "--json")
	}

	result, err := t.exec.Run(ctx, "feroxbuster", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("feroxbuster execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Feroxbuster Results: %s\n\n", input.URL)
	fmt.Fprintf(&sb, "Found %d result(s):\n\n", len(lines))
	sb.WriteString("```\n")
	sb.WriteString(output)
	sb.WriteString("\n```\n")

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

func validateURL(u string) error {
	if u == "" {
		return fmt.Errorf("url is required")
	}
	if len(u) > 4096 {
		return fmt.Errorf("url too long")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}
	forbidden := []string{";", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(u, c) {
			return fmt.Errorf("url contains forbidden character: %q", c)
		}
	}
	return nil
}
