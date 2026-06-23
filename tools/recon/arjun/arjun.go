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
	URL       string `json:"url"`
	Method    string `json:"method,omitempty"`
	Headers   string `json:"headers,omitempty"`
	Wordlist  string `json:"wordlist,omitempty"`
	Threads   int    `json:"threads,omitempty"`
	Delay     int    `json:"delay,omitempty"`
	Include   string `json:"include,omitempty"`
	Stable    bool   `json:"stable,omitempty"`
	Passive   bool   `json:"passive,omitempty"`
}

type ArjunTool struct {
	exec *executor.BinaryExecutor
}

func NewArjun(exec *executor.BinaryExecutor) *ArjunTool {
	return &ArjunTool{exec: exec}
}

func (t *ArjunTool) Name() string { return "arjun_discover" }

func (t *ArjunTool) Description() string {
	return "HTTP parameter discovery tool. Finds hidden GET/POST parameters using smart heuristics and a large wordlist. Supports JSON, form-data, and XML parameter types."
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
