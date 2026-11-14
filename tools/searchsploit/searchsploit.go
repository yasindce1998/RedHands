// Package searchsploit wraps the searchsploit CLI that ships with the
// exploitdb distro package, closing the loop from scanner findings to
// actionable exploits: nuclei finding -> CVE ID -> EDB-ID/exploit file ->
// Metasploit module (msf_module_run).
//
// searchsploit is a bash script (v4.x) that greps the local files_*.csv
// database installed alongside it; every tool here is read-only against that
// database. Verified against the upstream script
// (gitlab.com/exploit-database/exploitdb, bin at repo root):
//
//   - -j/--json emits a single JSON object with SEARCH, DB_PATH_* and
//     RESULTS_* array keys (empirically valid JSON, including the empty
//     case). Each result carries Title, EDB-ID, Codes, Verified, Path etc.
//   - --cve <CVE-YYYY-NNNN> fixed-string-greps the CSV line including the
//     Codes column, so the full prefixed (upper- or lowercase) ID matches.
//   - --path <EDB-ID> prints the exploit record (URL, Path, Codes,
//     Verified, File Type).
//   - --exclude=<term> is interpolated into `grep -viE`, so it is a regex on
//     the searchsploit side; because the sandboxed binary executor forbids
//     regex metacharacters (| ( ) { } etc.) in arguments, this wrapper only
//     accepts a single plain exclusion term.
//   - Long flags are parsed anywhere in argv; any argument starting with "-"
//     becomes flags, and any argument CONTAINING "--exclude=" is treated as
//     the exclude flag. Queries are therefore rejected if they start with
//     "-" or contain "--".
//
// searchsploit is a distro package (Kali/Debian: apt install exploitdb; Arch:
// AUR exploitdb; macOS: brew install exploitdb), not a checksum-pinnable
// binary — the operator must install it manually together with its on-disk
// database, as documented in each tool description.
package searchsploit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// searchsploitBinary is the exploitdb package's CLI (distro-managed, not
// checksum-pinnable — like msfconsole it must be allowlisted manually).
const searchsploitBinary = "searchsploit"

// shellMetachars mirrors the forbidden-character set enforced by the binary
// executor (pkg/executor/sandbox.go): any argument containing one of these
// is rejected before launch. Validating here produces actionable errors
// instead of opaque executor failures.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

var (
	// cveRegex matches a full CVE identifier, case-insensitive.
	cveRegex = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)
	// cveExtractRegex finds CVE identifiers inside free text such as a
	// nuclei finding block (word-bounded so "XCVE-..." does not match).
	cveExtractRegex = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	// edbIDRegex matches a numeric Exploit-DB ID.
	edbIDRegex = regexp.MustCompile(`^[0-9]{1,9}$`)
	// excludeRegex matches a single plain exclusion term: no regex
	// metacharacters (the sandboxed executor forbids them anyway).
	excludeRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._+ -]{0,63}$`)
	// msfModuleRegex matches a Metasploit exploit module reference
	// (lowercase, like the EDB tree it mirrors).
	msfModuleRegex = regexp.MustCompile(`^exploit/[a-z0-9][a-z0-9/_.+-]*$`)
	// edbPathRegex extracts the "Path:" line from `searchsploit --path`.
	edbPathRegex = regexp.MustCompile(`(?m)^\s*Path:\s*(\S+)\s*$`)
	// jsonPathRegex extracts quoted Path values from searchsploit output
	// when the JSON could not be parsed.
	jsonPathRegex = regexp.MustCompile(`"Path"\s*:\s*"([^"]+)"`)
)

const (
	maxQueryLen   = 512
	maxTextLen    = 65536
	maxExcludeLen = 64
	// maxEnrichCVEs bounds the number of searchsploit invocations a single
	// cve_enrich call may trigger when scanning free text.
	maxEnrichCVEs = 5
)

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

// validateSafeString rejects executor-forbidden shell metacharacters.
func validateSafeString(s, field string) error {
	if len(s) > 4096 {
		return fmt.Errorf("%s too long (max 4096 chars)", field)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validateQuery enforces the free-text search rules: non-empty, metachar- and
// flag-safe (searchsploit eats arguments starting with "-" or containing
// "--exclude=" as flags, silently dropping them from the search terms).
func validateQuery(query string) error {
	query = strings.TrimSpace(query)
	if query == "" {
		return fmt.Errorf("query is required")
	}
	if len(query) > maxQueryLen {
		return fmt.Errorf("query too long (max %d chars)", maxQueryLen)
	}
	if strings.HasPrefix(query, "-") {
		return fmt.Errorf("query must not start with '-' (searchsploit would parse it as a flag): %s", query)
	}
	if strings.Contains(query, "--") {
		return fmt.Errorf("query must not contain '--' (searchsploit would parse it as a long flag such as --exclude=): %s", query)
	}
	return validateSafeString(query, "query")
}

// validateExclude enforces a single plain exclusion term (optional field).
func validateExclude(exclude string) error {
	exclude = strings.TrimSpace(exclude)
	if exclude == "" {
		return nil
	}
	if len(exclude) > maxExcludeLen {
		return fmt.Errorf("exclude too long (max %d chars)", maxExcludeLen)
	}
	if !excludeRegex.MatchString(exclude) {
		return fmt.Errorf("exclude must be a single plain term matching ^[A-Za-z0-9][A-Za-z0-9/._+ -]*$ (e.g. PoC or dos; regex metacharacters such as | ( ) are forbidden by the sandboxed executor)")
	}
	return nil
}

// normalizeCVE validates and canonicalizes a CVE identifier to uppercase
// CVE-YYYY-NNNN form.
func normalizeCVE(s string) (string, error) {
	cve := strings.ToUpper(strings.TrimSpace(s))
	if !cveRegex.MatchString(cve) {
		return "", fmt.Errorf("cve must match ^CVE-[0-9]{4}-[0-9]{4,}$ case-insensitively, e.g. CVE-2021-44228 (got %q)", s)
	}
	return cve, nil
}

// extractCVEs returns the distinct CVE identifiers found in free text,
// normalized to uppercase and in order of first appearance.
func extractCVEs(text string) []string {
	seen := make(map[string]bool)
	var cves []string
	for _, m := range cveExtractRegex.FindAllString(text, -1) {
		cve := strings.ToUpper(m)
		if !seen[cve] {
			seen[cve] = true
			cves = append(cves, cve)
		}
	}
	return cves
}

// validateEDBID validates a numeric Exploit-DB ID, returning the trimmed ID.
func validateEDBID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("edb_id is required")
	}
	if !edbIDRegex.MatchString(id) {
		return "", fmt.Errorf("edb_id must be 1-9 digits (the numeric Exploit-DB ID, e.g. 39446)")
	}
	return id, nil
}

// msfModuleFromEDBPath maps an Exploit-DB file path such as
// /usr/share/exploitdb/exploits/linux/remote/12345.rb to the corresponding
// Metasploit module reference exploit/linux/remote/12345. Only Ruby (.rb)
// exploits under exploits/ map (shellcodes and papers never do; Metasploit
// does not mirror .py/.txt proof-of-concepts). The result is a candidate:
// the caller should confirm the module exists (msf_module_info) before
// running it with msf_module_run.
func msfModuleFromEDBPath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	idx := strings.Index(path, "exploits/")
	if idx < 0 {
		return "", false
	}
	// Guard against directories that merely end in "exploits" (e.g.
	// "myexploits/..."): the segment must be a real path component.
	if idx > 0 && path[idx-1] != '/' {
		return "", false
	}
	rel := path[idx:]
	if !strings.HasSuffix(rel, ".rb") {
		return "", false
	}
	module := "exploit/" + strings.TrimSuffix(strings.TrimPrefix(rel, "exploits/"), ".rb")
	for _, seg := range strings.Split(module, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	if !msfModuleRegex.MatchString(module) {
		return "", false
	}
	return module, true
}

// edbResult is one entry of a searchsploit --json RESULTS_* array.
type edbResult struct {
	Title         string `json:"Title"`
	EDBID         string `json:"EDB-ID"`
	DatePublished string `json:"Date_Published"`
	Author        string `json:"Author"`
	Type          string `json:"Type"`
	Platform      string `json:"Platform"`
	Verified      string `json:"Verified"`
	Codes         string `json:"Codes"`
	Path          string `json:"Path"`
}

// parseSearchsploitJSON parses searchsploit --json output: one object with
// SEARCH, DB_PATH_<DB> and RESULTS_<DB> keys (RESULTS_EXPLOIT,
// RESULTS_SHELLCODE, ... depending on the installed databases). Keys are
// iterated in sorted order for deterministic output.
func parseSearchsploitJSON(stdout []byte) ([]edbResult, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &doc); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		if strings.HasPrefix(k, "RESULTS_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var results []edbResult
	for _, k := range keys {
		var rs []edbResult
		if err := json.Unmarshal(doc[k], &rs); err != nil {
			return nil, err
		}
		results = append(results, rs...)
	}
	return results, nil
}

// extractPathsFromRaw pulls quoted Path values out of unparsed searchsploit
// output; it is the fallback when --json output could not be parsed.
func extractPathsFromRaw(raw string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, m := range jsonPathRegex.FindAllStringSubmatch(raw, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			paths = append(paths, m[1])
		}
	}
	return paths
}

// runSearchsploitCVE runs `searchsploit --disable-colour --json --cve <CVE>`
// and returns the parsed results, the raw stdout and whether JSON parsing
// succeeded (callers fall back to the raw output when it did not).
func runSearchsploitCVE(ctx context.Context, exec executor.Executor, cve string) (results []edbResult, raw string, parsed bool, err error) {
	result, err := exec.Run(ctx, searchsploitBinary, "--disable-colour", "--json", "--cve", cve)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = strings.TrimSpace(string(result.Stderr))
		}
		return nil, "", false, fmt.Errorf(
			"searchsploit failed for %s: %v\n%s\nIs the exploitdb package installed and its database on disk (Kali/Debian: apt install exploitdb; Arch: AUR exploitdb; macOS: brew install exploitdb)?",
			cve, err, stderr)
	}
	raw = string(result.Stdout)
	results, perr := parseSearchsploitJSON(result.Stdout)
	if perr != nil {
		return nil, raw, false, nil
	}
	return results, raw, true, nil
}

// verifiedLabel renders the raw CSV verified flag (1/0) for tables.
func verifiedLabel(v string) string {
	switch v {
	case "1":
		return "Yes"
	case "0":
		return "No"
	}
	return mdCell(v)
}

// mdCell makes a string safe for a markdown table cell.
func mdCell(s string) string {
	return strings.NewReplacer("|", "/", "\n", " ", "\r", " ").Replace(strings.TrimSpace(s))
}

// renderResultsTable renders EDB results as a markdown table.
func renderResultsTable(results []edbResult) string {
	var sb strings.Builder
	sb.WriteString("| EDB-ID | Title | Type | Verified | Path |\n")
	sb.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s |\n",
			mdCell(r.EDBID), mdCell(r.Title), mdCell(r.Type), verifiedLabel(r.Verified), mdCell(r.Path))
	}
	return sb.String()
}

// fence wraps text in a fenced code block.
func fence(lang, s string) string {
	s = strings.TrimRight(s, "\n")
	if strings.TrimSpace(s) == "" {
		s = "(no output)"
	}
	return "```" + lang + "\n" + s + "\n```\n"
}
