package ffuf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type WebFuzzInput struct {
	URL            string `json:"url"`
	Wordlist       string `json:"wordlist"`
	Method         string `json:"method,omitempty"`
	Headers        string `json:"headers,omitempty"`
	Data           string `json:"data,omitempty"`
	MatchCodes     string `json:"match_codes,omitempty"`
	FilterCodes    string `json:"filter_codes,omitempty"`
	FilterSize     string `json:"filter_size,omitempty"`
	Threads        int    `json:"threads,omitempty"`
	RateLimit      int    `json:"rate_limit,omitempty"`
	Extensions     string `json:"extensions,omitempty"`
	AutoCalibrate  bool   `json:"autocalibrate,omitempty"`
	Recursion      bool   `json:"recursion,omitempty"`
	RecursionDepth int    `json:"recursion_depth,omitempty"`
	MatchLines     string `json:"match_lines,omitempty"`
	MatchRegex     string `json:"match_regex,omitempty"`
	FilterLines    string `json:"filter_lines,omitempty"`
	FilterWords    string `json:"filter_words,omitempty"`
	FilterRegex    string `json:"filter_regex,omitempty"`
	Timeout        int    `json:"timeout,omitempty"`
	MaxTime        int    `json:"max_time,omitempty"`
	Verbose        bool   `json:"verbose,omitempty"`
}

type WebFuzzTool struct {
	exec executor.Executor
}

func NewWebFuzz(exec executor.Executor) *WebFuzzTool {
	return &WebFuzzTool{exec: exec}
}

func (t *WebFuzzTool) Name() string { return "ffuf_fuzz" }

func (t *WebFuzzTool) Description() string {
	return "Web fuzzer for directory/file discovery, parameter fuzzing, and virtual host enumeration. Supports auto-calibration, recursion, regex matching/filtering, and rate limiting. Use FUZZ keyword in URL for injection point."
}

func (t *WebFuzzTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL with FUZZ keyword (e.g., 'https://example.com/FUZZ')"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to wordlist file for fuzzing"
			},
			"method": {
				"type": "string",
				"enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
				"description": "HTTP method (default: GET)"
			},
			"headers": {
				"type": "string",
				"description": "Custom headers (format: 'Header: Value', comma-separated for multiple)"
			},
			"data": {
				"type": "string",
				"description": "POST data (use FUZZ keyword for injection point)"
			},
			"match_codes": {
				"type": "string",
				"description": "Match HTTP status codes (e.g., '200,301,302')"
			},
			"filter_codes": {
				"type": "string",
				"description": "Filter out HTTP status codes (e.g., '404,403')"
			},
			"filter_size": {
				"type": "string",
				"description": "Filter out responses of specific size"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 40)"
			},
			"rate_limit": {
				"type": "integer",
				"description": "Rate limit (requests per second)"
			},
			"extensions": {
				"type": "string",
				"description": "File extensions to append (e.g., 'php,html,txt')"
			},
			"autocalibrate": {
				"type": "boolean",
				"description": "Automatically calibrate filtering options"
			},
			"recursion": {
				"type": "boolean",
				"description": "Enable recursive scanning of discovered directories"
			},
			"recursion_depth": {
				"type": "integer",
				"description": "Maximum recursion depth (default: 0 = infinite)"
			},
			"match_lines": {
				"type": "string",
				"description": "Match responses with specific line count (e.g., '10' or '10-50')"
			},
			"match_regex": {
				"type": "string",
				"description": "Match responses containing regex pattern"
			},
			"filter_lines": {
				"type": "string",
				"description": "Filter responses by line count"
			},
			"filter_words": {
				"type": "string",
				"description": "Filter responses by word count"
			},
			"filter_regex": {
				"type": "string",
				"description": "Filter responses matching regex pattern"
			},
			"timeout": {
				"type": "integer",
				"description": "HTTP request timeout in seconds (default: 10)"
			},
			"max_time": {
				"type": "integer",
				"description": "Maximum total execution time in seconds"
			},
			"verbose": {
				"type": "boolean",
				"description": "Verbose output (show full URLs and redirect locations)"
			}
		},
		"required": ["url", "wordlist"]
	}`)
}

func (t *WebFuzzTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input WebFuzzInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := validateWordlist(input.Wordlist); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.URL, "-w", input.Wordlist, "-s"}

	if input.Method != "" {
		args = append(args, "-X", input.Method)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "-H", h)
			}
		}
	}
	if input.Data != "" {
		args = append(args, "-d", input.Data)
	}
	if input.MatchCodes != "" {
		args = append(args, "-mc", input.MatchCodes)
	}
	if input.FilterCodes != "" {
		args = append(args, "-fc", input.FilterCodes)
	}
	if input.FilterSize != "" {
		args = append(args, "-fs", input.FilterSize)
	}
	if input.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", input.Threads))
	}
	if input.RateLimit > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", input.RateLimit))
	}
	if input.Extensions != "" {
		args = append(args, "-e", input.Extensions)
	}
	if input.AutoCalibrate {
		args = append(args, "-ac")
	}
	if input.Recursion {
		args = append(args, "-recursion")
	}
	if input.RecursionDepth > 0 {
		args = append(args, "-recursion-depth", fmt.Sprintf("%d", input.RecursionDepth))
	}
	if input.MatchLines != "" {
		args = append(args, "-ml", input.MatchLines)
	}
	if input.MatchRegex != "" {
		args = append(args, "-mr", input.MatchRegex)
	}
	if input.FilterLines != "" {
		args = append(args, "-fl", input.FilterLines)
	}
	if input.FilterWords != "" {
		args = append(args, "-fw", input.FilterWords)
	}
	if input.FilterRegex != "" {
		args = append(args, "-fr", input.FilterRegex)
	}
	if input.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", input.Timeout))
	}
	if input.MaxTime > 0 {
		args = append(args, "-maxtime", fmt.Sprintf("%d", input.MaxTime))
	}
	if input.Verbose {
		args = append(args, "-v")
	}

	result, err := t.exec.Run(ctx, "ffuf", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("ffuf execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: "## Fuzzing Results\n\nNo results found."}},
		}, nil
	}

	lines := strings.Split(output, "\n")
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Fuzzing Results: %s\n\nFound %d result(s):\n\n", input.URL, len(lines))
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
	if !strings.Contains(url, "FUZZ") {
		return fmt.Errorf("url must contain FUZZ keyword as injection point")
	}
	return nil
}

func validateWordlist(path string) error {
	if path == "" {
		return fmt.Errorf("wordlist is required")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\""}
	for _, c := range forbidden {
		if strings.Contains(path, c) {
			return fmt.Errorf("wordlist path contains forbidden character: %q", c)
		}
	}
	return nil
}
