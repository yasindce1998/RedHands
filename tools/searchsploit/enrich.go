package searchsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// EnrichTool is the chaining glue from scanner findings to Metasploit: it
// takes a CVE (directly or extracted from free text such as a nuclei finding)
// and maps it to EDB exploits and candidate Metasploit modules.
type EnrichTool struct {
	exec executor.Executor
}

// NewEnrich creates the CVE enrichment tool.
func NewEnrich(exec executor.Executor) *EnrichTool {
	return &EnrichTool{exec: exec}
}

func (t *EnrichTool) Name() string { return "cve_enrich" }

func (t *EnrichTool) Description() string {
	return "Enrich a CVE with public exploit intelligence: takes a CVE ID directly or free text (e.g. a " +
		"nuclei finding or scanner report block — CVE IDs are extracted locally with a CVE-YYYY-NNNN " +
		"pattern, the text itself is never passed to a shell), runs `searchsploit --cve` for each CVE and " +
		"renders the matching EDB exploits. Exploit file paths under exploits/ ending in .rb map to " +
		"Metasploit module references (exploits/linux/remote/12345.rb -> exploit/linux/remote/12345), so the " +
		"result lists concrete msf_module_run candidates — confirm the module exists with msf_module_info " +
		"first, module names mapped from EDB paths are candidates, not guarantees. The explicit " +
		"nuclei-finding -> CVE -> EDB exploit -> msf_module_run path. Read-only against the local exploitdb " +
		"database; at most 5 distinct CVEs are enriched per call. searchsploit ships as a distro package " +
		"together with its on-disk database (Kali/Debian: apt install exploitdb; Arch: AUR exploitdb; " +
		"macOS: brew install exploitdb) — a manual, non-pinnable install the operator must perform. " +
		"Authorized security engagements only."
}

func (t *EnrichTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"cve": {
				"type": "string",
				"pattern": "^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$",
				"description": "CVE identifier, case-insensitive, normalized to uppercase (e.g. CVE-2021-44228); takes precedence over text"
			},
			"text": {
				"type": "string",
				"description": "Free text scanned for CVE-YYYY-NNNN patterns, e.g. a nuclei finding block; the first 5 distinct CVE IDs are enriched (the text is never passed to a shell)"
			}
		}
	}`)
}

type enrichInput struct {
	CVE  string `json:"cve"`
	Text string `json:"text"`
}

func (t *EnrichTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input enrichInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	var cves []string
	source := ""
	switch {
	case strings.TrimSpace(input.CVE) != "":
		cve, err := normalizeCVE(input.CVE)
		if err != nil {
			return errorResult(err.Error()), nil
		}
		cves = []string{cve}
		source = "direct"
	case strings.TrimSpace(input.Text) != "":
		if len(input.Text) > maxTextLen {
			return errorResult(fmt.Sprintf("text too long (max %d chars)", maxTextLen)), nil
		}
		found := extractCVEs(input.Text)
		if len(found) == 0 {
			return errorResult("no CVE IDs found in text (expected pattern CVE-YYYY-NNNN, e.g. CVE-2021-44228)"), nil
		}
		if len(found) > maxEnrichCVEs {
			return errorResult(fmt.Sprintf(
				"text contains %d distinct CVE IDs (%s); pass cve directly or narrow the text (max %d per call)",
				len(found), strings.Join(found, ", "), maxEnrichCVEs)), nil
		}
		cves = found
		source = "extracted from text"
	default:
		return errorResult("either cve or text is required"), nil
	}

	var sb strings.Builder
	sb.WriteString("## CVE Enrichment\n\n")
	fmt.Fprintf(&sb, "**CVEs**: %s (%s)\n\n", strings.Join(cves, ", "), source)

	failures := 0
	for _, cve := range cves {
		fmt.Fprintf(&sb, "### %s\n\n", cve)

		results, raw, parsed, err := runSearchsploitCVE(ctx, t.exec, cve)
		if err != nil {
			failures++
			sb.WriteString("**searchsploit failed**: " + err.Error() + "\n\n")
			continue
		}

		var paths []string
		if parsed {
			if len(results) == 0 {
				sb.WriteString("No EDB exploits reference this CVE in the local exploitdb database.\n\n")
			} else {
				fmt.Fprintf(&sb, "%d EDB exploit(s):\n\n", len(results))
				sb.WriteString(renderResultsTable(results) + "\n")
			}
			for _, r := range results {
				paths = append(paths, r.Path)
			}
		} else {
			// JSON parsing failed; fall back to regex path extraction.
			paths = extractPathsFromRaw(raw)
			sb.WriteString("(searchsploit returned non-JSON output; paths extracted with a fallback scan.)\n\n")
		}

		var modules []string
		seenModule := make(map[string]bool)
		for _, p := range paths {
			if module, ok := msfModuleFromEDBPath(p); ok && !seenModule[module] {
				seenModule[module] = true
				modules = append(modules, module)
			}
		}
		if len(modules) > 0 {
			for _, module := range modules {
				fmt.Fprintf(&sb, "- Metasploit: try msf_module_run with module %s\n", module)
			}
			sb.WriteString("\n(Only .rb exploits under exploits/ map to Metasploit module names; confirm with msf_module_info before running.)\n\n")
		} else {
			sb.WriteString("**Metasploit**: no module candidates (no Ruby exploits under exploits/ for this CVE).\n\n")
		}
	}

	sb.WriteString("### Next steps\n\n")
	sb.WriteString("- Local file path and copy command for an EDB-ID above: `searchsploit_edb`\n")
	sb.WriteString("- Confirm a module candidate exists before running it: `msf_module_info`\n")
	sb.WriteString("- Run the module against the target (authorized engagements only, approval-gated): `msf_module_run`\n")

	text := sb.String()
	if failures == len(cves) {
		// Every searchsploit invocation failed (e.g. exploitdb not installed).
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: text}},
			IsError: true,
		}, nil
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: text}},
	}, nil
}
