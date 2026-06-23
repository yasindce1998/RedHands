package gobuster

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type DirBustInput struct {
	URL        string `json:"url"`
	Wordlist   string `json:"wordlist"`
	Mode       string `json:"mode,omitempty"`
	Extensions string `json:"extensions,omitempty"`
	StatusHide string `json:"status_hide,omitempty"`
	Threads    int    `json:"threads,omitempty"`
	FollowRedir bool  `json:"follow_redirect,omitempty"`
	NoTLSValid bool   `json:"no_tls_validation,omitempty"`
}

type DirBustTool struct {
	exec *executor.BinaryExecutor
}

func NewDirBust(exec *executor.BinaryExecutor) *DirBustTool {
	return &DirBustTool{exec: exec}
}

func (t *DirBustTool) Name() string { return "gobuster_dir" }

func (t *DirBustTool) Description() string {
	return "Directory/file brute-forcing tool. Supports dir, dns, vhost, fuzz, and s3 modes for comprehensive enumeration."
}

func (t *DirBustTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL (e.g., 'https://example.com')"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to wordlist file"
			},
			"mode": {
				"type": "string",
				"enum": ["dir", "dns", "vhost", "fuzz", "s3"],
				"description": "Gobuster mode (default: dir)"
			},
			"extensions": {
				"type": "string",
				"description": "File extensions to check (e.g., 'php,html,js,txt')"
			},
			"status_hide": {
				"type": "string",
				"description": "Hide responses with these status codes (e.g., '404,403')"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 10)"
			},
			"follow_redirect": {
				"type": "boolean",
				"description": "Follow HTTP redirects"
			},
			"no_tls_validation": {
				"type": "boolean",
				"description": "Skip TLS certificate validation"
			}
		},
		"required": ["url", "wordlist"]
	}`)
}

func (t *DirBustTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DirBustInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Wordlist); err != nil {
		return errorResult("invalid wordlist: " + err.Error()), nil
	}

	mode := "dir"
	if input.Mode != "" {
		mode = input.Mode
	}

	args := []string{mode, "-u", input.URL, "-w", input.Wordlist, "-q", "--no-color"}

	if input.Extensions != "" {
		args = append(args, "-x", input.Extensions)
	}
	if input.StatusHide != "" {
		args = append(args, "-b", input.StatusHide)
	}
	if input.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", input.Threads))
	}
	if input.FollowRedir {
		args = append(args, "-r")
	}
	if input.NoTLSValid {
		args = append(args, "-k")
	}

	result, err := t.exec.Run(ctx, "gobuster", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("gobuster execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var found []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			found = append(found, l)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Gobuster (%s): %s\n\n", mode, input.URL)
	fmt.Fprintf(&sb, "Found %d result(s):\n\n", len(found))
	for _, f := range found {
		fmt.Fprintf(&sb, "- %s\n", f)
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

func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\""}
	for _, c := range forbidden {
		if strings.Contains(path, c) {
			return fmt.Errorf("path contains forbidden character: %q", c)
		}
	}
	return nil
}
