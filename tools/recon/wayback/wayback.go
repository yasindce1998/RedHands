package wayback

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type WaybackInput struct {
	Domain     string `json:"domain"`
	NoSubs     bool   `json:"no_subs,omitempty"`
	GetVersions bool  `json:"get_versions,omitempty"`
}

type WaybackTool struct {
	exec *executor.BinaryExecutor
}

func NewWayback(exec *executor.BinaryExecutor) *WaybackTool {
	return &WaybackTool{exec: exec}
}

func (t *WaybackTool) Name() string { return "waybackurls" }

func (t *WaybackTool) Description() string {
	return "Fetch known URLs for a domain from the Wayback Machine (web.archive.org). Useful for discovering historical endpoints, parameters, and hidden paths."
}

func (t *WaybackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Target domain (e.g., example.com)"
			},
			"no_subs": {
				"type": "boolean",
				"description": "Do not include subdomains in results"
			},
			"get_versions": {
				"type": "boolean",
				"description": "Get all archived versions of each URL"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *WaybackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input WaybackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateDomain(input.Domain); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Domain}
	if input.NoSubs {
		args = append(args, "-no-subs")
	}
	if input.GetVersions {
		args = append(args, "-get-versions")
	}

	result, err := t.exec.Run(ctx, "waybackurls", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("waybackurls execution failed: %s\n%s", err.Error(), stderr)), nil
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
	fmt.Fprintf(&sb, "## Wayback URLs: %s\n\n", input.Domain)
	fmt.Fprintf(&sb, "Found %d archived URL(s):\n\n", len(urls))
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

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(domain, c) {
			return fmt.Errorf("domain contains forbidden character: %q", c)
		}
	}
	return nil
}
