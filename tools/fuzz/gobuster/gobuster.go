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
	URL           string `json:"url,omitempty"`
	Domain        string `json:"domain,omitempty"`
	Wordlist      string `json:"wordlist"`
	Mode          string `json:"mode,omitempty"`
	Extensions    string `json:"extensions,omitempty"`
	StatusHide    string `json:"status_hide,omitempty"`
	StatusShow    string `json:"status_show,omitempty"`
	Threads       int    `json:"threads,omitempty"`
	FollowRedir   bool   `json:"follow_redirect,omitempty"`
	NoTLSValid    bool   `json:"no_tls_validation,omitempty"`
	Proxy         string `json:"proxy,omitempty"`
	Cookies       string `json:"cookies,omitempty"`
	Headers       string `json:"headers,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Delay         string `json:"delay,omitempty"`
	AppendDomain  bool   `json:"append_domain,omitempty"`
	WildcardForce bool   `json:"wildcard_force,omitempty"`
}

type DirBustTool struct {
	exec executor.Executor
}

func NewDirBust(exec executor.Executor) *DirBustTool {
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
				"description": "Target URL for dir/vhost/fuzz/s3 modes (e.g., 'https://example.com')"
			},
			"domain": {
				"type": "string",
				"description": "Target domain for dns mode (e.g., 'example.com')"
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
				"description": "File extensions to check in dir mode (e.g., 'php,html,js,txt')"
			},
			"status_hide": {
				"type": "string",
				"description": "Hide responses with these status codes (e.g., '404,403')"
			},
			"status_show": {
				"type": "string",
				"description": "Show only responses with these status codes (e.g., '200,301')"
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
			},
			"proxy": {
				"type": "string",
				"description": "Proxy URL (e.g., 'http://127.0.0.1:8080')"
			},
			"cookies": {
				"type": "string",
				"description": "Cookies to send with requests (e.g., 'session=abc123')"
			},
			"headers": {
				"type": "string",
				"description": "Custom headers, semicolon-separated (e.g., 'X-Token: abc;X-Custom: val')"
			},
			"user_agent": {
				"type": "string",
				"description": "Custom User-Agent string"
			},
			"username": {
				"type": "string",
				"description": "Username for basic auth"
			},
			"password": {
				"type": "string",
				"description": "Password for basic auth"
			},
			"delay": {
				"type": "string",
				"description": "Delay between requests (e.g., '500ms', '1s')"
			},
			"append_domain": {
				"type": "boolean",
				"description": "Append base domain to vhost enumeration results"
			},
			"wildcard_force": {
				"type": "boolean",
				"description": "Force processing of wildcard DNS responses"
			}
		},
		"required": ["wordlist"]
	}`)
}

func (t *DirBustTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DirBustInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePath(input.Wordlist); err != nil {
		return errorResult("invalid wordlist: " + err.Error()), nil
	}

	mode := "dir"
	if input.Mode != "" {
		mode = input.Mode
	}

	var args []string

	switch mode {
	case "dns":
		if input.Domain == "" {
			return errorResult("domain is required for dns mode"), nil
		}
		if err := validateDomain(input.Domain); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{mode, "-d", input.Domain, "-w", input.Wordlist, "-q", "--no-color"}
		if input.WildcardForce {
			args = append(args, "--wildcard")
		}
	case "vhost":
		if input.URL == "" {
			return errorResult("url is required for vhost mode"), nil
		}
		if err := validateURL(input.URL); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{mode, "-u", input.URL, "-w", input.Wordlist, "-q", "--no-color"}
		if input.Domain != "" {
			args = append(args, "--domain", input.Domain)
		}
		if input.AppendDomain {
			args = append(args, "--append-domain")
		}
	default:
		if input.URL == "" {
			return errorResult("url is required for " + mode + " mode"), nil
		}
		if err := validateURL(input.URL); err != nil {
			return errorResult(err.Error()), nil
		}
		args = []string{mode, "-u", input.URL, "-w", input.Wordlist, "-q", "--no-color"}
	}

	if input.Extensions != "" && (mode == "dir" || mode == "fuzz") {
		args = append(args, "-x", input.Extensions)
	}
	if input.StatusHide != "" {
		args = append(args, "-b", input.StatusHide)
	}
	if input.StatusShow != "" {
		args = append(args, "-s", input.StatusShow)
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
	if input.Proxy != "" {
		args = append(args, "--proxy", input.Proxy)
	}
	if input.Cookies != "" {
		args = append(args, "-c", input.Cookies)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, ";") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "-H", h)
			}
		}
	}
	if input.UserAgent != "" {
		args = append(args, "-a", input.UserAgent)
	}
	if input.Username != "" {
		args = append(args, "-U", input.Username)
	}
	if input.Password != "" {
		args = append(args, "-P", input.Password)
	}
	if input.Delay != "" {
		args = append(args, "--delay", input.Delay)
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

	target := input.URL
	if mode == "dns" {
		target = input.Domain
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Gobuster (%s): %s\n\n", mode, target)
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

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", " ", "'", "\"", "\\", "/"}
	for _, c := range forbidden {
		if strings.Contains(domain, c) {
			return fmt.Errorf("domain contains forbidden character: %q", c)
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
