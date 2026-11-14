package searchsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// SearchTool searches the local Exploit-DB database for public exploits
// matching free-text terms.
type SearchTool struct {
	exec executor.Executor
}

// NewSearch creates the free-text Exploit-DB search tool.
func NewSearch(exec executor.Executor) *SearchTool {
	return &SearchTool{exec: exec}
}

func (t *SearchTool) Name() string { return "searchsploit_search" }

func (t *SearchTool) Description() string {
	return "Search the local Exploit-DB database for public exploits and proof-of-concepts matching " +
		"free-text terms (AND semantics, e.g. 'oracle windows' or 'apache log4j'): wraps searchsploit with " +
		"--json structured output by default or the ASCII table view, optional title-only matching " +
		"(-t/--title, removes false positives on version numbers) and a single plain exclusion term " +
		"(--exclude, e.g. PoC or dos). Read-only and fully offline once the database is installed. " +
		"Chain: feed CVE IDs from scanner findings (e.g. nuclei) to searchsploit_cve or cve_enrich, resolve " +
		"EDB-IDs to local exploit file paths with searchsploit_edb, and run matching Metasploit modules with " +
		"msf_module_run. searchsploit ships as a distro package together with its on-disk database " +
		"(Kali/Debian: apt install exploitdb; Arch: AUR exploitdb; macOS: brew install exploitdb) — a " +
		"manual, non-pinnable install the operator must perform. Authorized security engagements only."
}

func (t *SearchTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query": {
				"type": "string",
				"description": "Free-text search terms (space-separated AND search), e.g. 'oracle windows' or 'linux kernel 3.2'; must not start with '-' or contain '--' (searchsploit parses those as flags)"
			},
			"title_only": {
				"type": "boolean",
				"description": "Search just the exploit title instead of title + file path (-t/--title); removes false positives, especially when searching version numbers"
			},
			"exclude": {
				"type": "string",
				"description": "Single plain exclusion term (--exclude=...), e.g. 'PoC' or 'dos'; regex metacharacters such as | ( ) are forbidden by the sandboxed executor"
			},
			"json": {
				"type": "boolean",
				"description": "Return searchsploit --json structured output (default true); false renders the ASCII table"
			}
		},
		"required": ["query"]
	}`)
}

type searchInput struct {
	Query     string `json:"query"`
	TitleOnly bool   `json:"title_only"`
	Exclude   string `json:"exclude"`
	JSON      *bool  `json:"json"`
}

func (t *SearchTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input searchInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	query := strings.TrimSpace(input.Query)
	if err := validateQuery(query); err != nil {
		return errorResult(err.Error()), nil
	}
	exclude := strings.TrimSpace(input.Exclude)
	if err := validateExclude(exclude); err != nil {
		return errorResult(err.Error()), nil
	}
	jsonMode := true
	if input.JSON != nil {
		jsonMode = *input.JSON
	}

	// Long flags only (parsed by searchsploit's explicit elif chain, never
	// by getopts), in a fixed order for deterministic executor calls.
	args := []string{"--disable-colour"}
	if jsonMode {
		args = append(args, "--json")
	}
	if input.TitleOnly {
		args = append(args, "--title")
	}
	if exclude != "" {
		args = append(args, "--exclude="+exclude)
	}
	args = append(args, query)

	result, err := t.exec.Run(ctx, searchsploitBinary, args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = strings.TrimSpace(string(result.Stderr))
		}
		return errorResult(fmt.Sprintf(
			"searchsploit failed: %v\n%s\nIs the exploitdb package installed and its database on disk (Kali/Debian: apt install exploitdb; Arch: AUR exploitdb; macOS: brew install exploitdb)?",
			err, stderr)), nil
	}

	var sb strings.Builder
	sb.WriteString("## SearchSploit Search\n\n")
	fmt.Fprintf(&sb, "**Query**: %s\n", query)
	if input.TitleOnly {
		sb.WriteString("**Mode**: title-only\n")
	}
	if exclude != "" {
		fmt.Fprintf(&sb, "**Exclude**: %s\n", exclude)
	}
	sb.WriteString("\n")
	if jsonMode {
		sb.WriteString(fence("json", string(result.Stdout)))
	} else {
		sb.WriteString(fence("", string(result.Stdout)))
	}
	sb.WriteString("\nNotes:\n\n")
	sb.WriteString("- Resolve an EDB-ID from the results to a local exploit file path: `searchsploit_edb`\n")
	sb.WriteString("- Map CVE IDs to EDB exploits and Metasploit module candidates: `searchsploit_cve` / `cve_enrich`\n")
	sb.WriteString("- Run a matching Metasploit module (authorized engagements only): `msf_module_run`\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
