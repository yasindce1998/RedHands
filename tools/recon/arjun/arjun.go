package arjun

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ArjunInput struct {
	URL              string `json:"url"`
	Method           string `json:"method,omitempty"`
	Headers          string `json:"headers,omitempty"`
	Wordlist         string `json:"wordlist,omitempty"`
	Threads          int    `json:"threads,omitempty"`
	Delay            int    `json:"delay,omitempty"`
	Include          string `json:"include,omitempty"`
	Stable           bool   `json:"stable,omitempty"`
	Passive          bool   `json:"passive,omitempty"`
	OutputJSON       bool   `json:"output_json,omitempty"`
	ChunkSize        int    `json:"chunk_size,omitempty"`
	Timeout          int    `json:"timeout,omitempty"`
	RateLimit        int    `json:"rate_limit,omitempty"`
	DisableRedirects bool   `json:"disable_redirects,omitempty"`
}

type ArjunTool struct {
	exec executor.Executor
}

func NewArjun(exec executor.Executor) *ArjunTool {
	return &ArjunTool{exec: exec}
}

func (t *ArjunTool) Name() string { return "arjun_discover" }

func (t *ArjunTool) Description() string {
	return "HTTP parameter discovery tool. Finds hidden GET/POST/JSON/XML parameters using smart heuristics and a large wordlist. Supports chunked requests, rate limiting, and passive discovery."
}

func (t *ArjunTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL to discover parameters on"
			},
			"method": {
				"type": "string",
				"enum": ["GET", "POST", "JSON", "XML"],
				"description": "HTTP method / parameter type (default: GET)"
			},
			"headers": {
				"type": "string",
				"description": "Custom headers (semicolon-separated, e.g., 'Cookie: sess=abc;X-Token: xyz')"
			},
			"wordlist": {
				"type": "string",
				"description": "Custom wordlist path for parameter names"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 2)"
			},
			"delay": {
				"type": "integer",
				"description": "Delay between requests in seconds"
			},
			"include": {
				"type": "string",
				"description": "Comma-separated parameters to include in every request"
			},
			"stable": {
				"type": "boolean",
				"description": "Enable stable mode (slower but more reliable)"
			},
			"passive": {
				"type": "boolean",
				"description": "Only use passive sources (CommonCrawl, Wayback, etc.)"
			},
			"output_json": {
				"type": "boolean",
				"description": "Output results in JSON format"
			},
			"chunk_size": {
				"type": "integer",
				"description": "Number of parameters per request chunk (default: 250)"
			},
			"timeout": {
				"type": "integer",
				"description": "HTTP request timeout in seconds (default: 15)"
			},
			"rate_limit": {
				"type": "integer",
				"description": "Maximum requests per second"
			},
			"disable_redirects": {
				"type": "boolean",
				"description": "Disable following HTTP redirects"
			}
		},
		"required": ["url"]
	}`)
}

func (t *ArjunTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ArjunInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.URL}

	if input.Method != "" {
		args = append(args, "-m", input.Method)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, ";") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "--headers", h)
			}
		}
	}
	if input.Wordlist != "" {
		args = append(args, "-w", input.Wordlist)
	}
	if input.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", input.Threads))
	}
	if input.Delay > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", input.Delay))
	}
	if input.Include != "" {
		args = append(args, "--include", input.Include)
	}
	if input.Stable {
		args = append(args, "--stable")
	}
	if input.Passive {
		args = append(args, "--passive")
	}
	if input.OutputJSON {
		args = append(args, "-oJ", "-")
	}
	if input.ChunkSize > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", input.ChunkSize))
	}
	if input.Timeout > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", input.Timeout))
	}
	if input.RateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", input.RateLimit))
	}
	if input.DisableRedirects {
		args = append(args, "--disable-redirects")
	}

	result, err := t.exec.Run(ctx, "arjun", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("arjun execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Arjun Parameter Discovery: %s\n\n", input.URL)
	if output == "" {
		sb.WriteString("No parameters discovered.\n")
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
