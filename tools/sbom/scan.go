package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Exit code 2 from `grype` means "vulnerabilities found at or above the
// --fail-on severity" (cmd/grype/cli/cli.go maps grypeerr.ErrAboveSeverityThreshold
// to exit code 2; every other failure exits 1). Like barzakh-scanner's exit-1
// detection, this is a valid command result with the full JSON report on
// stdout, not an execution failure. Note the inversion relative to barzakh:
// for grype, exit 1 is a real error and exit 2 is the detection signal.
const exitCodeFindingsAboveThreshold = 2

// scanInput is the shared parameter set for both grype wrappers.
type scanInput struct {
	Source     string `json:"source,omitempty"`
	SbomFile   string `json:"sbom_file,omitempty"`
	Severity   string `json:"severity,omitempty"`
	OnlyFixed  bool   `json:"only_fixed,omitempty"`
	FailOn     string `json:"fail_on,omitempty"`
	OutputFile string `json:"output_file,omitempty"`
}

// ImageScanTool wraps `grype <source>` for image/directory vulnerability scanning.
type ImageScanTool struct {
	exec executor.Executor
}

// NewVulnScanImage returns a grype-backed image vulnerability scanner.
func NewVulnScanImage(exec executor.Executor) *ImageScanTool {
	return &ImageScanTool{exec: exec}
}

func (t *ImageScanTool) Name() string { return "vuln_scan_image" }

func (t *ImageScanTool) Description() string {
	return "Scan a container image, filesystem directory, or SBOM for known vulnerabilities with Anchore grype. " +
		"The source can be an image reference (alpine:latest, registry:... — pulls from registries, needs network) " +
		"or a local form (dir:/path, docker-archive:./img.tar, sbom:/path/to/syft.json — no image pull). " +
		"grype always needs its vulnerability database: on first run (and periodically) it downloads the DB, which requires network; " +
		"the DB is cached under ~/.cache/grype. Returns a severity summary plus the full grype JSON in a ```json fence for campaign record rules. " +
		"When fail_on is set and matches at/above that severity are found, grype exits 2 — reported as a findings result, not an error."
}

func (t *ImageScanTool) InputSchema() json.RawMessage {
	return scanInputSchema("source", "Grype source: image reference (alpine:latest, registry:repo/img:tag) or local form (dir:/path, docker-archive:./img.tar, sbom:syft.json). Image references pull from registries = network")
}

func (t *ImageScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input scanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateSource(input.Source, "source"); err != nil {
		return errorResult(err.Error()), nil
	}
	return runGrypeScan(ctx, t.exec, input, input.Source, "## Image Vulnerability Scan (grype)\n")
}

// SbomScanTool wraps `grype sbom:<file>` for scanning an existing SBOM.
type SbomScanTool struct {
	exec executor.Executor
}

// NewVulnScanSbom returns a grype-backed SBOM vulnerability scanner.
func NewVulnScanSbom(exec executor.Executor) *SbomScanTool {
	return &SbomScanTool{exec: exec}
}

func (t *SbomScanTool) Name() string { return "vuln_scan_sbom" }

func (t *SbomScanTool) Description() string {
	return "Scan an existing SBOM file (e.g. produced by sbom_generate) for known vulnerabilities with Anchore grype (sbom:<path> source). " +
		"Reading the SBOM itself is offline, but grype still needs its vulnerability database: on first run (and periodically) it downloads the DB from the network; " +
		"the DB is cached under ~/.cache/grype. Returns a severity summary plus the full grype JSON in a ```json fence for campaign record rules. " +
		"When fail_on is set and matches at/above that severity are found, grype exits 2 — reported as a findings result, not an error."
}

func (t *SbomScanTool) InputSchema() json.RawMessage {
	return scanInputSchema("sbom_file", "Path to an existing SBOM file (syft-json, cyclonedx-json, or spdx-json); scanned as grype sbom:<path>")
}

func (t *SbomScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input scanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateExistingFile(input.SbomFile, "sbom_file"); err != nil {
		return errorResult(err.Error()), nil
	}
	return runGrypeScan(ctx, t.exec, input, "sbom:"+input.SbomFile, "## SBOM Vulnerability Scan (grype)\n")
}

func scanInputSchema(sourceField, sourceDesc string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{
		"type": "object",
		"properties": {
			%q: {
				"type": "string",
				"description": %q
			},
			"severity": {
				"type": "string",
				"enum": ["negligible", "low", "medium", "high", "critical"],
				"description": "Minimum severity to keep in the summary and fenced JSON (client-side filter on the matches array; grype v0.121.3 has no --severity output flag). The scan itself still runs unfiltered"
			},
			"only_fixed": {
				"type": "boolean",
				"description": "Ignore matches for vulnerabilities with no available fix (grype --only-fixed)"
			},
			"fail_on": {
				"type": "string",
				"enum": ["negligible", "low", "medium", "high", "critical"],
				"description": "Severity threshold for grype --fail-on: matches at/above it make grype exit 2, reported as a findings result with the full report (not an error)"
			},
			"output_file": {
				"type": "string",
				"description": "Optional path to also write the grype JSON report to (passed as -o json=<path>; stdout JSON is still captured and returned). Note: the file copy is not affected by the severity filter"
			}
		},
		"required": [%q]
	}`, sourceField, sourceDesc, sourceField))
}

// runGrypeScan executes grype against the given source argument and renders
// the shared result: header, severity summary, top matches, and the fenced
// JSON document.
func runGrypeScan(ctx context.Context, exec executor.Executor, input scanInput, sourceArg, title string) (*mcp.ToolResult, error) {
	if input.Severity != "" && !severityValid(input.Severity) {
		return errorResult("severity must be one of: " + strings.Join(grypeSeverities, ", ")), nil
	}
	if input.FailOn != "" && !severityValid(input.FailOn) {
		return errorResult("fail_on must be one of: " + strings.Join(grypeSeverities, ", ")), nil
	}
	if err := validatePath(input.OutputFile, "output_file"); err != nil {
		return errorResult(err.Error()), nil
	}

	// -o json emits the report on stdout (captured and fenced below); an
	// additional -o json=<path> writes a file copy (grype supports multiple
	// -o outputs, verified against internal/format/writer.go v0.121.3).
	args := []string{sourceArg, "-o", "json"}
	if input.OutputFile != "" {
		args = append(args, "-o", "json="+input.OutputFile)
	}
	if input.OnlyFixed {
		args = append(args, "--only-fixed")
	}
	if input.FailOn != "" {
		args = append(args, "--fail-on", input.FailOn)
	}

	result, thresholdExceeded, err := runWithFindingsExit(ctx, exec, exitCodeFindingsAboveThreshold, "grype", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("grype failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString(title + "\n")
	fmt.Fprintf(&sb, "- **Source:** %s\n", sourceArg)
	if input.OnlyFixed {
		sb.WriteString("- **Filter:** only vulnerabilities with a fix\n")
	}
	if input.Severity != "" {
		fmt.Fprintf(&sb, "- **Severity filter:** >= %s (applied to the fenced JSON; grype ran unfiltered)\n", input.Severity)
	}
	if input.OutputFile != "" {
		fmt.Fprintf(&sb, "- **File:** %s\n", input.OutputFile)
	}
	if thresholdExceeded {
		if input.FailOn != "" {
			fmt.Fprintf(&sb, "- **Result:** ⚠️ VULNERABILITIES AT/ABOVE --fail-on %s THRESHOLD (grype exit code 2)\n", input.FailOn)
		} else {
			sb.WriteString("- **Result:** ⚠️ findings-threshold exit (grype exit code 2) without --fail-on requested — grype behavior change?\n")
		}
	} else if input.FailOn != "" {
		fmt.Fprintf(&sb, "- **Result:** no matches at/above the --fail-on %s threshold\n", input.FailOn)
	}
	sb.WriteString("\n")

	// The severity filter is client-side (grype v0.121.3 has no --severity
	// output flag): the fenced document is re-marshaled from the filtered
	// matches so summary, fence, and record rules stay consistent.
	report := output
	if input.Severity != "" && json.Valid([]byte(output)) {
		if filtered, ok := filterMatchesBySeverity(output, input.Severity); ok {
			report = filtered
		}
	}

	if summary, ok := summarizeMatches(report); ok {
		sb.WriteString(summary)
		sb.WriteString("\n")
	}
	if preview, ok := topMatches(report, 10); ok {
		sb.WriteString(preview)
		sb.WriteString("\n")
	}

	switch {
	case report != "" && json.Valid([]byte(report)):
		sb.WriteString("```json\n")
		sb.WriteString(report)
		sb.WriteString("\n```\n")
	case report != "":
		sb.WriteString("```\n")
		sb.WriteString(report)
		sb.WriteString("\n```\n")
	case thresholdExceeded:
		sb.WriteString("grype reported threshold-exceeding matches (exit 2) but produced no JSON output.\n")
	default:
		sb.WriteString("Scan completed with no report output.\n")
	}

	return textResult(sb.String()), nil
}

func severityValid(s string) bool {
	for _, v := range grypeSeverities {
		if v == s {
			return true
		}
	}
	return false
}

// runWithFindingsExit executes the binary and treats findingsExit as a
// successful "findings found" outcome rather than an error, mirroring
// tools/barzakh/scan.go's runWithDetectionExit. The executor turns every
// non-zero process exit into an error but returns the Result (with ExitCode
// and captured stdout/stderr) alongside it; timeouts, cancellations, and
// truncated output produce different error texts, so the executor's
// "execution failed (exit N)" message is matched to confirm a genuine
// process exit.
func runWithFindingsExit(ctx context.Context, exec executor.Executor, findingsExit int, binary string, args ...string) (*executor.Result, bool, error) {
	result, err := exec.Run(ctx, binary, args...)
	if err == nil {
		return result, false, nil
	}
	if result != nil && result.ExitCode == findingsExit && isProcessExitError(err, findingsExit) {
		return result, true, nil
	}
	return result, false, err
}

// isProcessExitError reports whether err is the executor's error for a normal
// process exit with the given code (not a timeout, cancellation, or
// truncated-output error).
func isProcessExitError(err error, code int) bool {
	return err != nil && strings.Contains(err.Error(), fmt.Sprintf("execution failed (exit %d)", code))
}

// grypeDocument mirrors the grype JSON presenter shape (v0.121.3,
// grype/presenter/models): matches, source, distro, descriptor
// (ignoredMatches is omitempty).
type grypeDocument struct {
	Matches []grypeMatch `json:"matches"`
	Source  struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"distro"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Fix         struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		Purl    string `json:"purl"`
	} `json:"artifact"`
}

// severityOrder renders grype severities most severe first (grype emits
// capitalized values like "Critical"; unknown severities sort last).
var severityOrder = []string{"critical", "high", "medium", "low", "negligible", "unknown"}

// summarizeMatches renders a per-severity match count plus source/distro
// lines from a grype JSON document. ok=false means the output was not
// recognizable grype JSON (pass it through raw instead).
func summarizeMatches(report string) (string, bool) {
	var doc grypeDocument
	if report == "" || !json.Valid([]byte(report)) {
		return "", false
	}
	if err := json.Unmarshal([]byte(report), &doc); err != nil || doc.Matches == nil {
		return "", false
	}

	counts := make(map[string]int)
	for _, m := range doc.Matches {
		severity := normalizeSeverity(m.Vulnerability.Severity)
		if severity == "" {
			severity = "unknown"
		}
		counts[severity]++
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "- **Matches:** %d\n", len(doc.Matches))
	for _, severity := range severityOrder {
		if counts[severity] > 0 {
			fmt.Fprintf(&sb, "  - %s: %d\n", severity, counts[severity])
			delete(counts, severity)
		}
	}
	rest := make([]string, 0, len(counts))
	for severity := range counts {
		rest = append(rest, severity)
	}
	sort.Strings(rest)
	for _, severity := range rest {
		fmt.Fprintf(&sb, "  - %s: %d\n", severity, counts[severity])
	}

	if src := describeSource(doc); src != "" {
		fmt.Fprintf(&sb, "- **Scanned:** %s\n", src)
	}
	if doc.Distro.Name != "" {
		fmt.Fprintf(&sb, "- **Distro:** %s %s\n", doc.Distro.Name, doc.Distro.Version)
	}
	if doc.Descriptor.Version != "" {
		fmt.Fprintf(&sb, "- **Grype version:** %s\n", doc.Descriptor.Version)
	}
	return sb.String(), true
}

// describeSource renders the grype source: image sources carry a target
// object with userInput/imageID; directory and SBOM sources use a plain
// string target.
func describeSource(doc grypeDocument) string {
	if doc.Source.Type == "" {
		return ""
	}
	target := ""
	if len(doc.Source.Target) > 0 {
		var obj struct {
			UserInput string `json:"userInput"`
			ImageID   string `json:"imageID"`
			Path      string `json:"path"`
		}
		if err := json.Unmarshal(doc.Source.Target, &obj); err == nil && (obj.UserInput != "" || obj.ImageID != "" || obj.Path != "") {
			switch {
			case obj.UserInput != "":
				target = obj.UserInput
			case obj.Path != "":
				target = obj.Path
			default:
				target = obj.ImageID
			}
		} else {
			var s string
			if err := json.Unmarshal(doc.Source.Target, &s); err == nil {
				target = s
			}
		}
	}
	if target == "" {
		return doc.Source.Type
	}
	return fmt.Sprintf("%s (%s)", target, doc.Source.Type)
}

// topMatches renders a short preview of the most severe matches:
// CVE id, severity, package@version, and fix state.
func topMatches(report string, n int) (string, bool) {
	var doc grypeDocument
	if report == "" || !json.Valid([]byte(report)) {
		return "", false
	}
	if err := json.Unmarshal([]byte(report), &doc); err != nil || len(doc.Matches) == 0 {
		return "", false
	}

	matches := append([]grypeMatch(nil), doc.Matches...)
	sort.SliceStable(matches, func(i, j int) bool {
		return severityRank[normalizeSeverity(matches[i].Vulnerability.Severity)] > severityRank[normalizeSeverity(matches[j].Vulnerability.Severity)]
	})
	if len(matches) > n {
		matches = matches[:n]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "- **Top matches (by severity):**\n")
	for _, m := range matches {
		fix := m.Vulnerability.Fix.State
		if fix == "" {
			fix = "unknown"
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fix = "fixed in " + strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		fmt.Fprintf(&sb, "  - %s [%s] %s@%s (%s, fix: %s)\n",
			m.Vulnerability.ID,
			normalizeSeverity(m.Vulnerability.Severity),
			m.Artifact.Name,
			m.Artifact.Version,
			m.Artifact.Type,
			fix,
		)
	}
	return sb.String(), true
}

// filterMatchesBySeverity drops matches below the minimum severity from a
// grype JSON document and re-marshals it. Unknown severities are kept only
// when the threshold is negligible. The original document (with matched
// severities capitalized, e.g. "High") is preserved verbatim apart from the
// filtered matches array; ok=false means the input was not grype JSON.
func filterMatchesBySeverity(report, minSeverity string) (string, bool) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(report), &doc); err != nil {
		return "", false
	}
	matchesRaw, ok := doc["matches"].([]any)
	if !ok {
		return "", false
	}
	minRank, ok := severityRank[minSeverity]
	if !ok {
		return "", false
	}

	kept := make([]any, 0, len(matchesRaw))
	for _, m := range matchesRaw {
		severity := "unknown"
		if obj, ok := m.(map[string]any); ok {
			if vuln, ok := obj["vulnerability"].(map[string]any); ok {
				if s, ok := vuln["severity"].(string); ok {
					severity = normalizeSeverity(s)
					if severity == "" {
						severity = "unknown"
					}
				}
			}
		}
		if severityRank[severity] >= minRank {
			kept = append(kept, m)
		}
	}

	doc["matches"] = kept
	filtered, err := json.Marshal(doc)
	if err != nil {
		return "", false
	}
	return string(filtered), true
}
