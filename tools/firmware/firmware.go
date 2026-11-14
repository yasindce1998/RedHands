// Package firmware wraps binwalk v2 (ReFirmLabs) — the ubiquitous Python
// firmware analysis tool — for signature scanning, extraction, and entropy
// analysis of embedded firmware images. It complements the UEFI (tools/barzakh)
// and baseband (tools/telecom) firmware toolsets with generic embedded
// firmware analysis.
//
// CLI verification notes (binwalk v2.3.1, the last 2.x release and the version
// targeted here; verified against the v2.3.1 tag sources, NOT master, which is
// now the v3 Rust rewrite):
//
//   - `binwalk <file>` is the default signature scan; -B/--signature enables
//     it explicitly. The wrappers always pass -B so the module mix is
//     deterministic regardless of the other flags.
//   - -A/--opcodes (signature.py) scans for executable opcode signatures; it
//     REPLACES the normal magic files unless -B is also passed, so the scan
//     wrapper passes -B alongside -A to make opcodes additive.
//   - -E/--entropy (entropy.py) runs entropy analysis. When no other module
//     produced results, entropy rows (rising/falling edges only, in
//     non-verbose mode) are displayed; when signature results exist, entropy
//     rows are suppressed. The module plots via matplotlib plt.show() unless
//     -N/--nplot is passed — which would hang a headless MCP invocation — so
//     the wrappers ALWAYS pass -N together with -E.
//   - -K/--block (general.py) sets the file block size; the entropy module
//     uses config.block when set, otherwise auto-sizes blocks for ~2048
//     data points.
//   - -y/--include and -x/--exclude (signature.py) take Python regexes, but
//     the executor forbids shell metacharacters in every argument, so only
//     simple metachar-free patterns can be passed. That is documented in the
//     tool schemas.
//   - --csv/-c (general.py) does NOT put CSV on stdout: display.py only
//     enables the csv.writer when a -f/--log file is also given. Structured
//     output therefore requires `--csv -f <logfile> -q` and reading the log
//     file afterwards. binwalk v2 has NO JSON output at all (v3 does, via
//     --log); the JSON summaries in these tools are built locally by parsing
//     the CSV log.
//   - CSV row quirk: display.result passes the raw result columns
//     [offset, offset, description] to csv.writerow, so the column under the
//     "HEXADECIMAL" header actually contains the DECIMAL offset again. The
//     parsers here read the first column and compute the hex form locally.
//     Verbose runs (forced by recursive extraction) also interleave
//     [FILE, MD5SUM, TIMESTAMP] rows and repeated header rows; the parser
//     skips every row whose first field is not a non-negative integer.
//   - -e/--extract enables auto-extraction with the default extract.conf
//     rules; -D/--dd <type:ext[:cmd]> extracts only matching signatures (a
//     third colon component is an external command binwalk would execute via
//     subprocess — deliberately NOT exposed by these wrappers).
//   - v2.3.1 DOES have -C/--directory <dir> (extractor.py): the base
//     directory for extraction output (created if missing). Extraction lands
//     in <directory>/_<image basename>.extracted/ (with a -N suffix on name
//     collision). This corrects the common assumption that v2 can only
//     extract next to the image; the extract wrapper passes -C directly.
//   - -d/--depth N (extractor.py) sets the matryoshka recursion depth; it
//     enables recursive extraction on its own (-M is the shorthand for the
//     default depth of 8).
//   - Exit codes (src/binwalk/__main__.py): 0 on a normal scan — including
//     when zero signatures are found; 1 when no arguments were given;
//     2 when signature-scan support is missing (python-lzma); 3 on
//     ModuleException (e.g. an unreadable target file or an invalid
//     include/exclude regex). Only 0 is treated as success here.
//
// binwalk v3 (the current master, a Rust rewrite) has a DIFFERENT flag
// surface — e.g. -E conflicts with -e, --log emits JSON (with '-' for
// stdout), -C/--directory defaults to "extractions", and --csv/--dd/-A/-d do
// not exist — so these wrappers must not be used against v3 binaries.
package firmware

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// binwalkBinary is the executable every tool in this package invokes.
const binwalkBinary = "binwalk"

// authorizedUseNotice is appended to every tool description.
const authorizedUseNotice = " Wraps binwalk (ReFirmLabs); authorized analysis of firmware images you own or have explicit permission to analyze."

// shellMetachars mirrors the executor's argument validation list (plus quotes
// and backslash, rejected early for clearer errors). Every user-supplied
// string that reaches argv is checked against this list before the run.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

const maxSafeStringLen = 4096

func validateSafeString(s, field string) error {
	if s == "" {
		return nil
	}
	if len(s) > maxSafeStringLen {
		return fmt.Errorf("%s too long (max %d chars)", field, maxSafeStringLen)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validateImageFile ensures the firmware image path exists and is a regular
// file, failing fast before binwalk runs (binwalk reports unreadable targets
// only via a ModuleException on stderr).
func validateImageFile(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(path, field); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file, not a directory", field)
	}
	return nil
}

// validateOutputDir enforces a non-empty metachar-free directory path and
// ensures it exists, creating it (and parents) with 0700 when missing. It is
// the extraction base directory passed to binwalk -C.
func validateOutputDir(dir, field string) error {
	if dir == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(dir, field); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is a file, not a directory: %s", field, dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot access %s %s: %v", field, dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create %s %s: %v", field, dir, err)
	}
	return nil
}

// validatePositiveInt validates an optional integer parameter with the given
// inclusive bounds (used for -d/--depth and -K/--block).
func validatePositiveInt(field string, value *int64, min, max int64) error {
	if value == nil {
		return nil
	}
	if *value < min || *value > max {
		return fmt.Errorf("%s must be between %d and %d", field, min, max)
	}
	return nil
}

// ddRuleRegex matches the two-part --dd carve rule <type>:<ext> that the
// extract wrapper accepts. The third colon component of binwalk's full
// <type>:<ext>:<command> rule format is an arbitrary external command
// binwalk would execute via subprocess; exposing it would be a command
// injection vector, so only the carve-only form is allowed.
var ddRuleRegex = regexp.MustCompile(`^[A-Za-z0-9_.+*-]+:[A-Za-z0-9_.*+-]+$`)

// validateDDRule validates a --dd carve rule. The rule must be exactly
// <signature>:<extension> (e.g. "squashfs:*.sqfs"); rules with a command
// component are rejected.
func validateDDRule(rule string) error {
	if rule == "" {
		return nil
	}
	if err := validateSafeString(rule, "dd"); err != nil {
		return err
	}
	if !ddRuleRegex.MatchString(rule) {
		return fmt.Errorf("invalid dd rule %q: must be <signature>:<extension> (e.g. squashfs:*.sqfs); the optional command component of binwalk --dd rules is not exposed", rule)
	}
	return nil
}

// runBinwalk executes binwalk and returns stdout plus an error result on
// failure. binwalk v2.3.1 exits 0 even when no signatures are found; exit 3
// is a ModuleException (unreadable file, invalid regex), exit 2 means
// signature-scan support is missing.
func runBinwalk(ctx context.Context, exec executor.Executor, args []string) (string, *mcp.ToolResult) {
	result, err := exec.Run(ctx, binwalkBinary, args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return "", errorResult(fmt.Sprintf("binwalk failed: %s\n%s", err.Error(), stderr))
	}
	stdout := ""
	if result != nil {
		stdout = string(result.Stdout)
	}
	return stdout, nil
}

// newCSVLog creates the temporary file binwalk's -f/--log writes the CSV
// results to (--csv only takes effect when -f is given). The caller must
// remove the file when done.
func newCSVLog() (string, error) {
	f, err := os.CreateTemp("", "redhands-binwalk-*.csv")
	if err != nil {
		return "", fmt.Errorf("cannot create temporary CSV log: %v", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("cannot close temporary CSV log: %v", err)
	}
	return f.Name(), nil
}

// signatureRow is one parsed result row from a binwalk CSV log. OffsetHex is
// computed locally: binwalk's CSV "HEXADECIMAL" column actually repeats the
// decimal offset (see the package comment).
type signatureRow struct {
	Offset      int64  `json:"offset"`
	OffsetHex   string `json:"offset_hex"`
	Description string `json:"description"`
}

// parseBinwalkCSV parses the CSV log written by `binwalk --csv -f <log>`.
// Rows whose first field is not a non-negative integer are skipped: that
// covers the DECIMAL/HEXADECIMAL/DESCRIPTION header row, the
// FILE/MD5SUM/TIMESTAMP rows verbose runs interleave, and per-file path rows
// from recursive scans.
func parseBinwalkCSV(data []byte) []signatureRow {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	var rows []signatureRow
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 3 {
			continue
		}
		offset, err := strconv.ParseInt(strings.TrimSpace(record[0]), 10, 64)
		if err != nil || offset < 0 {
			continue
		}
		rows = append(rows, signatureRow{
			Offset:      offset,
			OffsetHex:   fmt.Sprintf("0x%X", offset),
			Description: strings.TrimSpace(strings.Join(record[2:], ",")),
		})
	}
	return rows
}

// readCSVLog reads the CSV log binwalk was asked to write. ok=false when the
// file is missing or empty (the run is then reported from stdout instead).
func readCSVLog(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// removeLog discards the temporary CSV log after the result was built from
// it. Failure to remove is not reported: the file lives in the system temp
// directory.
func removeLog(path string) {
	_ = os.Remove(path)
}

// findExtractionDirectory returns the directory binwalk extracted into:
// <outputDir>/_<image basename>.extracted, or the unique -N suffixed variant
// binwalk creates on name collisions. When nothing was extracted, the
// canonical expected path is still returned.
func findExtractionDirectory(outputDir, image string) string {
	canonical := filepath.Join(outputDir, "_"+filepath.Base(image)+".extracted")
	if info, err := os.Stat(canonical); err == nil && info.IsDir() {
		return canonical
	}
	matches, _ := filepath.Glob(filepath.Join(outputDir, "_"+filepath.Base(image)+".extracted*"))
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil && info.IsDir() {
			return match
		}
	}
	return canonical
}

// extractedFile is one file produced by extraction, relative to the output
// directory.
type extractedFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// listExtractedFiles walks dir and returns up to maxEntries extracted files
// (relative paths with sizes) plus the total file count.
func listExtractedFiles(dir string, maxEntries int) ([]extractedFile, int) {
	var files []extractedFile
	total := 0
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total++
		if len(files) < maxEntries {
			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				rel = path
			}
			files = append(files, extractedFile{Path: rel, Bytes: info.Size()})
		}
		return nil
	})
	return files, total
}

// marshalSummary renders a summary struct as indented JSON for the fenced
// JSON block in tool results.
func marshalSummary(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func textResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
	}
}
