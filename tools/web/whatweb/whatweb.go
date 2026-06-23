package whatweb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type FingerprintInput struct {
	Target     string `json:"target"`
	Aggression int    `json:"aggression,omitempty"`
	Verbose    bool   `json:"verbose,omitempty"`
	Proxy      string `json:"proxy,omitempty"`
	Cookie     string `json:"cookie,omitempty"`
	Headers    string `json:"headers,omitempty"`
	Plugins    string `json:"plugins,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	MaxThreads int    `json:"max_threads,omitempty"`
	URLPrefix  string `json:"url_prefix,omitempty"`
	URLSuffix  string `json:"url_suffix,omitempty"`
}

type FingerprintTool struct {
	exec executor.Executor
}

func NewFingerprint(exec executor.Executor) *FingerprintTool {
	return &FingerprintTool{exec: exec}
}

func (t *FingerprintTool) Name() string { return "whatweb_fingerprint" }

func (t *FingerprintTool) Description() string {
	return "Web technology fingerprinting tool. Identifies CMS, frameworks, JavaScript libraries, web servers, embedded devices, and more. Supports proxy, custom headers, plugin selection, and URL prefix/suffix for path manipulation."
}

func (t *FingerprintTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target URL or host (e.g., 'https://example.com')"
			},
			"aggression": {
				"type": "integer",
				"description": "Aggression level 1-4 (1=stealthy, 3=aggressive, 4=heavy)"
			},
			"verbose": {
				"type": "boolean",
				"description": "Enable verbose output with detailed plugin results"
			},
			"proxy": {
				"type": "string",
				"description": "HTTP proxy URL (e.g., 'http://127.0.0.1:8080')"
			},
			"cookie": {
				"type": "string",
				"description": "Cookie string to send with requests (e.g., 'session=abc123;token=xyz')"
			},
			"headers": {
				"type": "string",
				"description": "Custom headers (semicolon-separated, e.g., 'X-Custom: value;Authorization: Bearer token')"
			},
			"plugins": {
				"type": "string",
				"description": "Comma-separated plugins to use (e.g., 'Apache,PHP,WordPress')"
			},
			"user_agent": {
				"type": "string",
				"description": "Custom User-Agent string"
			},
			"max_threads": {
				"type": "integer",
				"description": "Maximum number of concurrent threads (default: 25)"
			},
			"url_prefix": {
				"type": "string",
				"description": "URL prefix to prepend to target paths"
			},
			"url_suffix": {
				"type": "string",
				"description": "URL suffix to append to target paths"
			}
		},
		"required": ["target"]
	}`)
}

func (t *FingerprintTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FingerprintInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTarget(input.Target); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{input.Target, "--color=never", "--no-errors"}

	if input.Aggression > 0 {
		args = append(args, fmt.Sprintf("-a=%d", input.Aggression))
	}
	if input.Verbose {
		args = append(args, "-v")
	}
	if input.Proxy != "" {
		args = append(args, "--proxy", input.Proxy)
	}
	if input.Cookie != "" {
		args = append(args, "--cookie", input.Cookie)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, ";") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "--header", h)
			}
		}
	}
	if input.Plugins != "" {
		args = append(args, "-p", input.Plugins)
	}
	if input.UserAgent != "" {
		args = append(args, "-U", input.UserAgent)
	}
	if input.MaxThreads > 0 {
		args = append(args, "--max-threads", fmt.Sprintf("%d", input.MaxThreads))
	}
	if input.URLPrefix != "" {
		args = append(args, "--url-prefix", input.URLPrefix)
	}
	if input.URLSuffix != "" {
		args = append(args, "--url-suffix", input.URLSuffix)
	}

	result, err := t.exec.Run(ctx, "whatweb", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("whatweb execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## WhatWeb Fingerprint: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("No results.\n")
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
