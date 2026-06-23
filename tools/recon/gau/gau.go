package gau

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type GAUInput struct {
	Target       string `json:"target"`
	Providers    string `json:"providers,omitempty"`
	Subs         bool   `json:"include_subs,omitempty"`
	Blacklist    string `json:"blacklist,omitempty"`
	MatchMime    string `json:"match_mime,omitempty"`
	FilterStatus string `json:"filter_status,omitempty"`
	FromDate     string `json:"from,omitempty"`
	ToDate       string `json:"to,omitempty"`
	Threads      int    `json:"threads,omitempty"`
	Verbose      bool   `json:"verbose,omitempty"`
	OutputJSON   bool   `json:"output_json,omitempty"`
	FetchFilters string `json:"fetch_filters,omitempty"`
}

type GAUTool struct {
	exec executor.Executor
}

func NewGAU(exec executor.Executor) *GAUTool {
	return &GAUTool{exec: exec}
}

func (t *GAUTool) Name() string { return "gau_urls" }

func (t *GAUTool) Description() string {
	return "Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl, and URLScan. Retrieves historical and indexed URLs for a given domain."
}

func (t *GAUTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target domain (e.g., 'example.com')"
			},
			"providers": {
				"type": "string",
				"description": "Comma-separated providers to use (wayback, commoncrawl, otx, urlscan)"
			},
			"include_subs": {
				"type": "boolean",
				"description": "Include subdomains"
			},
			"blacklist": {
				"type": "string",
				"description": "Comma-separated extensions to blacklist (e.g., 'png,jpg,gif,css')"
			},
			"match_mime": {
				"type": "string",
				"description": "Comma-separated MIME types to match/include (e.g., 'text/html,application/json')"
			},
			"filter_status": {
				"type": "string",
				"description": "Comma-separated status codes to filter/exclude (e.g., '404,403')"
			},
			"from": {
				"type": "string",
				"description": "Fetch URLs from this date (YYYYMM format, e.g., '202001')"
			},
			"to": {
				"type": "string",
				"description": "Fetch URLs up to this date (YYYYMM format, e.g., '202312')"
			},
			"threads": {
				"type": "integer",
				"description": "Number of threads (default: 2)"
			},
			"verbose": {
				"type": "boolean",
				"description": "Enable verbose output"
			},
			"output_json": {
				"type": "boolean",
				"description": "Output as JSON lines (includes status code, content type, etc.)"
			},
			"fetch_filters": {
				"type": "string",
				"description": "Comma-separated providers to filter from results (e.g., 'wayback,commoncrawl')"
			}
		},
		"required": ["target"]
	}`)
}

func (t *GAUTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input GAUInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateDomain(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Target}

	if input.Providers != "" {
		args = append(args, "--providers", input.Providers)
	}
	if input.Subs {
		args = append(args, "--subs")
	}
	if input.Blacklist != "" {
		args = append(args, "--blacklist", input.Blacklist)
	}
	if input.MatchMime != "" {
		args = append(args, "--mt", input.MatchMime)
	}
	if input.FilterStatus != "" {
		args = append(args, "--fc", input.FilterStatus)
	}
	if input.FromDate != "" {
		args = append(args, "--from", input.FromDate)
	}
	if input.ToDate != "" {
		args = append(args, "--to", input.ToDate)
	}
	if input.Threads > 0 {
		args = append(args, "--threads", fmt.Sprintf("%d", input.Threads))
	}
	if input.Verbose {
		args = append(args, "--verbose")
	}
	if input.OutputJSON {
		args = append(args, "--json")
	}
	if input.FetchFilters != "" {
		args = append(args, "--fp", input.FetchFilters)
	}

	result, err := t.exec.Run(ctx, "gau", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("gau execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")
	urlCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			urlCount++
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## GAU URL Results: %s\n\n", input.Target)
	fmt.Fprintf(&sb, "Fetched %d URL(s) from historical sources:\n\n", urlCount)
	if urlCount > 200 {
		sb.WriteString("```\n")
		shown := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				fmt.Fprintf(&sb, "%s\n", line)
				shown++
				if shown >= 200 {
					break
				}
			}
		}
		fmt.Fprintf(&sb, "\n... and %d more URLs\n", urlCount-200)
		sb.WriteString("```\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
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

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("target is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("target too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\", "/"}
	for _, c := range forbidden {
		if strings.Contains(domain, c) {
			return fmt.Errorf("target contains forbidden character: %q", c)
		}
	}
	return nil
}
