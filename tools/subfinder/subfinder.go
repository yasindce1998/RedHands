package subfinder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SubdomainEnumInput struct {
	Domain     string `json:"domain"`
	Recursive  bool   `json:"recursive,omitempty"`
	MaxDepth   int    `json:"max_depth,omitempty"`
	Sources    string `json:"sources,omitempty"`
	ExcludeSrc string `json:"exclude_sources,omitempty"`
}

type SubdomainEnumTool struct {
	exec *executor.BinaryExecutor
}

func NewSubdomainEnum(exec *executor.BinaryExecutor) *SubdomainEnumTool {
	return &SubdomainEnumTool{exec: exec}
}

func (t *SubdomainEnumTool) Name() string { return "subfinder_enum" }

func (t *SubdomainEnumTool) Description() string {
	return "Enumerate subdomains of a target domain using multiple passive sources (certificate logs, search engines, DNS datasets)."
}

func (t *SubdomainEnumTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Target domain to enumerate subdomains for (e.g., example.com)"
			},
			"recursive": {
				"type": "boolean",
				"description": "Enable recursive subdomain enumeration"
			},
			"max_depth": {
				"type": "integer",
				"description": "Maximum recursion depth (default: 5)"
			},
			"sources": {
				"type": "string",
				"description": "Comma-separated list of sources to use (e.g., 'crtsh,hackertarget')"
			},
			"exclude_sources": {
				"type": "string",
				"description": "Comma-separated list of sources to exclude"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *SubdomainEnumTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SubdomainEnumInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateDomain(input.Domain); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-d", input.Domain, "-silent"}

	if input.Recursive {
		args = append(args, "-recursive")
	}
	if input.MaxDepth > 0 {
		args = append(args, "-max-depth", fmt.Sprintf("%d", input.MaxDepth))
	}
	if input.Sources != "" {
		args = append(args, "-sources", input.Sources)
	}
	if input.ExcludeSrc != "" {
		args = append(args, "-exclude-sources", input.ExcludeSrc)
	}

	result, err := t.exec.Run(ctx, "subfinder", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("subfinder execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	subdomains := strings.Split(output, "\n")

	var filtered []string
	for _, s := range subdomains {
		s = strings.TrimSpace(s)
		if s != "" {
			filtered = append(filtered, s)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Subdomain Enumeration: %s\n\nFound %d subdomains:\n\n", input.Domain, len(filtered))
	for _, s := range filtered {
		fmt.Fprintf(&sb, "- %s\n", s)
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
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid domain format")
	}
	return nil
}
