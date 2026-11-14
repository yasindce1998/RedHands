package searchsploit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// EdbTool resolves a numeric Exploit-DB ID to the local exploit file path.
type EdbTool struct {
	exec executor.Executor
}

// NewEdb creates the EDB-ID-to-file-path lookup tool.
func NewEdb(exec executor.Executor) *EdbTool {
	return &EdbTool{exec: exec}
}

func (t *EdbTool) Name() string { return "searchsploit_edb" }

func (t *EdbTool) Description() string {
	return "Resolve a numeric Exploit-DB ID (EDB-ID, e.g. 39446 from a searchsploit_search/searchsploit_cve " +
		"result) to the local exploit file: wraps `searchsploit --path` and returns the exploit title, " +
		"exploit-db.com URL, full file path, CVE codes, verified flag and file type, plus a ready-to-use " +
		"copy command to pull the exploit into the working directory for review. Read-only (no mirroring is " +
		"performed). Chain: cve_enrich or searchsploit_cve produce the EDB-ID, this tool produces the file, " +
		"and Ruby exploits under exploits/ map to Metasploit module candidates runnable with msf_module_run. " +
		"searchsploit ships as a distro package together with its on-disk database (Kali/Debian: " +
		"apt install exploitdb; Arch: AUR exploitdb; macOS: brew install exploitdb) — a manual, " +
		"non-pinnable install the operator must perform. Authorized security engagements only."
}

func (t *EdbTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"edb_id": {
				"type": "string",
				"pattern": "^[0-9]{1,9}$",
				"description": "Numeric Exploit-DB ID, e.g. 39446 (digits only)"
			}
		},
		"required": ["edb_id"]
	}`)
}

type edbInput struct {
	EDBID string `json:"edb_id"`
}

func (t *EdbTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input edbInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	id, err := validateEDBID(input.EDBID)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	result, err := t.exec.Run(ctx, searchsploitBinary, "--disable-colour", "--path", id)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = strings.TrimSpace(string(result.Stderr))
		}
		return errorResult(fmt.Sprintf(
			"searchsploit failed: %v\n%s\nIs the exploitdb package installed and its database on disk (Kali/Debian: apt install exploitdb; Arch: AUR exploitdb; macOS: brew install exploitdb)?",
			err, stderr)), nil
	}

	out := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	sb.WriteString("## SearchSploit EDB-ID Lookup\n\n")
	fmt.Fprintf(&sb, "**EDB-ID**: %s\n\n", id)
	sb.WriteString(fence("", out))

	// Extract the exploit file path and emit a copy hint.
	if m := edbPathRegex.FindStringSubmatch(out); m != nil {
		fmt.Fprintf(&sb, "**Exploit file**: %s\n\n", m[1])
		sb.WriteString("Copy the exploit into the working directory for review:\n\n")
		sb.WriteString(fence("", "cp "+m[1]+" ."))
		fmt.Fprintf(&sb, "\n(equivalent to `searchsploit --mirror %s` — review the source before use)\n", id)
	}

	sb.WriteString("\nNotes:\n\n")
	sb.WriteString("- Ruby (.rb) exploits under exploits/ map to Metasploit module candidates: `cve_enrich` / `searchsploit_cve`\n")
	sb.WriteString("- Run a matching Metasploit module (authorized engagements only): `msf_module_run`\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
