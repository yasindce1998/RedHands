package searchsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// CveTool maps a CVE identifier to Exploit-DB exploits — the key chaining
// step from scanner findings (nuclei emits CVE IDs) to public exploits.
type CveTool struct {
	exec executor.Executor
}

// NewCve creates the CVE-to-Exploit-DB lookup tool.
func NewCve(exec executor.Executor) *CveTool {
	return &CveTool{exec: exec}
}

func (t *CveTool) Name() string { return "searchsploit_cve" }

func (t *CveTool) Description() string {
	return "Map a CVE identifier (e.g. CVE-2021-44228, case-insensitive) to public Exploit-DB exploits via " +
		"`searchsploit --cve`: returns EDB-IDs, titles and local exploit file paths as structured JSON " +
		"(searchsploit -j) plus a rendered table. THE chaining tool from vulnerability scanners: nuclei " +
		"findings carry CVE IDs, this resolves them to EDB-IDs and exploit paths; follow up with " +
		"searchsploit_edb for a file path and copy hint, cve_enrich to also map to Metasploit module " +
		"candidates for msf_module_run. Read-only against the local exploitdb database. searchsploit " +
		"ships as a distro package together with its on-disk database (Kali/Debian: apt install exploitdb; " +
		"Arch: AUR exploitdb; macOS: brew install exploitdb) — a manual, non-pinnable install the operator " +
		"must perform. Authorized security engagements only."
}

func (t *CveTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"cve": {
				"type": "string",
				"pattern": "^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$",
				"description": "CVE identifier, case-insensitive, normalized to uppercase (e.g. CVE-2021-44228)"
			}
		},
		"required": ["cve"]
	}`)
}

type cveInput struct {
	CVE string `json:"cve"`
}

func (t *CveTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input cveInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	if strings.TrimSpace(input.CVE) == "" {
		return errorResult("cve is required"), nil
	}
	cve, err := normalizeCVE(input.CVE)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	results, raw, parsed, err := runSearchsploitCVE(ctx, t.exec, cve)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## SearchSploit CVE Lookup\n\n")
	fmt.Fprintf(&sb, "**CVE**: %s\n\n", cve)

	if parsed {
		if len(results) == 0 {
			sb.WriteString("No EDB exploits reference this CVE in the local exploitdb database.\n\n")
		} else {
			fmt.Fprintf(&sb, "Found %d EDB exploit(s):\n\n", len(results))
			sb.WriteString(renderResultsTable(results) + "\n")
		}
		sb.WriteString("### Raw searchsploit JSON\n\n")
		sb.WriteString(fence("json", raw))
	} else {
		sb.WriteString("searchsploit returned non-JSON output (parsing failed); raw output below.\n\n")
		sb.WriteString(fence("", raw))
	}

	sb.WriteString("\nNotes:\n\n")
	sb.WriteString("- Resolve an EDB-ID above to a local file path and copy hint: `searchsploit_edb`\n")
	sb.WriteString("- Also map this CVE to Metasploit module candidates for `msf_module_run`: `cve_enrich`\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
