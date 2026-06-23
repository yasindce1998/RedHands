package katana

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CrawlInput struct {
	URL         string `json:"url"`
	Depth       int    `json:"depth,omitempty"`
	JSCrawl     bool   `json:"js_crawl,omitempty"`
	Headless    bool   `json:"headless,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	FormFill    bool   `json:"form_fill,omitempty"`
}

type CrawlTool struct {
	exec *executor.BinaryExecutor
}

func NewCrawl(exec *executor.BinaryExecutor) *CrawlTool {
	return &CrawlTool{exec: exec}
}

func (t *CrawlTool) Name() string { return "katana_crawl" }

func (t *CrawlTool) Description() string {
	return "Next-generation web crawler for discovering endpoints, JavaScript files, API routes, and forms. Supports headless browser crawling."
}

func (t *CrawlTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL to crawl (e.g., 'https://example.com')"
			},
			"depth": {
				"type": "integer",
				"description": "Maximum crawl depth (default: 3)"
			},
			"js_crawl": {
				"type": "boolean",
				"description": "Enable JavaScript file crawling and endpoint extraction"
			},
			"headless": {
				"type": "boolean",
				"description": "Use headless browser for JavaScript-rendered pages"
			},
			"scope": {
				"type": "string",
				"description": "Crawl scope: 'strict' (same host), 'domain' (same domain), 'subdomain' (include subdomains)"
			},
			"concurrency": {
				"type": "integer",
				"description": "Number of concurrent crawlers (default: 10)"
			},
			"form_fill": {
				"type": "boolean",
				"description": "Enable automatic form filling during crawling"
			}
		},
		"required": ["url"]
	}`)
}

func (t *CrawlTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CrawlInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.URL, "-silent"}

	if input.Depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", input.Depth))
	}
	if input.JSCrawl {
		args = append(args, "-jc")
	}
	if input.Headless {
		args = append(args, "-headless")
	}
	if input.Scope != "" {
		args = append(args, "-fs", input.Scope)
	}
	if input.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", input.Concurrency))
	}
	if input.FormFill {
		args = append(args, "-aff")
	}

	result, err := t.exec.Run(ctx, "katana", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("katana execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var urls []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			urls = append(urls, l)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Web Crawl: %s\n\n", input.URL)
	fmt.Fprintf(&sb, "Discovered %d endpoint(s):\n\n", len(urls))
	for _, u := range urls {
		fmt.Fprintf(&sb, "- %s\n", u)
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

func validateURL(url string) error {
	if url == "" {
		return fmt.Errorf("url is required")
	}
	if len(url) > 2048 {
		return fmt.Errorf("url too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(url, c) {
			return fmt.Errorf("url contains forbidden character: %q", c)
		}
	}
	return nil
}
