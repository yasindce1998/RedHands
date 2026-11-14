package sbom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// Golden pipeline tests against real tool output captured in
// testdata/sbom/ (see that directory's README for provenance):
//
//   - syft-dir-sbom.json / grype-sbom-scan.json — real runs of syft v1.57.1
//     (`syft dir:... -o json -q`) and grype v0.121.3 (`grype sbom:... -o json`)
//     against the same two-package go.mod.
//   - *-golden.json — upstream presenter/encoder unit-test goldens from the
//     syft/grype repos covering the image-source shapes.
//
// They verify the full wrapper path the campaign dataflow depends on:
// fixture stdout → exit-code handling → markdown ```json fence →
// workflow.StructuredFromText extraction → severity summary → record-rule
// field paths.

func loadGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sbom", name))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return data
}

func mustDecodeValue(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("decoding fixture JSON: %v", err)
	}
	return value
}

// --- sbom_generate golden ---

func TestSbomGenerateGolden_RealSyftOutputSummarizedAndFenced(t *testing.T) {
	stdout := loadGolden(t, "syft-dir-sbom.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewSbomGenerate(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "dir:/tmp/scan-target"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text

	// Recompute expectations from the fixture itself so assertions track the
	// real syft output, not a hand-written copy.
	var doc struct {
		Artifacts []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			Purl    string `json:"purl"`
		} `json:"artifacts"`
		Source struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"source"`
		Descriptor struct {
			Version string `json:"version"`
		} `json:"descriptor"`
	}
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("fixture is not syft-json: %v", err)
	}
	if len(doc.Artifacts) != 2 {
		t.Fatalf("fixture unexpectedly has %d artifacts (want the 2-package go.mod scan)", len(doc.Artifacts))
	}
	if !strings.Contains(text, "**Packages:** "+strconv.Itoa(len(doc.Artifacts))) {
		t.Errorf("package count missing from summary:\n%s", text)
	}
	if !strings.Contains(text, "**Source:** "+doc.Source.Name) {
		t.Errorf("source name missing from summary (real: %q):\n%s", doc.Source.Name, text)
	}
	if !strings.Contains(text, "go-module") {
		t.Errorf("package-type breakdown missing:\n%s", text)
	}
	for _, a := range doc.Artifacts {
		if !strings.Contains(text, a.Purl) {
			t.Errorf("package preview missing real purl %q:\n%s", a.Purl, text)
		}
	}

	// The raw SBOM must be fenced as ```json so campaign extraction can
	// reach it and vuln_scan_sbom can consume it.
	if !strings.Contains(text, "```json\n{") {
		t.Errorf("raw SBOM not fenced as json:\n%s", text)
	}
}

// The upstream encoder golden carries the image-source shape (source.metadata
// with imageID/layers) — the summary must not choke on it.
func TestSbomGenerateGolden_ImageSourceShapePassesThrough(t *testing.T) {
	stdout := loadGolden(t, "syft-image-sbom-encoder-golden.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewSbomGenerate(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "user-image-input"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "**Packages:** 2") {
		t.Errorf("image golden has 2 artifacts, summary missing count:\n%s", text)
	}
	if !strings.Contains(text, "```json\n{") {
		t.Errorf("raw SBOM not fenced as json:\n%s", text)
	}
}

// --- vuln_scan_* golden ---

func TestVulnScanGolden_RealGrypeOutputSummarizedAndFenced(t *testing.T) {
	stdout := loadGolden(t, "grype-sbom-scan.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewVulnScanSbom(mock)

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, loadGolden(t, "syft-dir-sbom.json"), 0o644); err != nil {
		t.Fatalf("writing temp SBOM: %v", err)
	}

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"sbom_file": sbomPath}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text

	// Recompute severity counts from the fixture itself.
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("fixture is not grype JSON: %v", err)
	}
	if len(doc.Matches) == 0 {
		t.Fatalf("real grype fixture unexpectedly clean")
	}
	counts := map[string]int{}
	for _, m := range doc.Matches {
		counts[strings.ToLower(m.Vulnerability.Severity)]++
	}
	if !strings.Contains(text, "**Matches:** "+strconv.Itoa(len(doc.Matches))) {
		t.Errorf("total match count missing from summary:\n%s", text)
	}
	for severity, n := range counts {
		want := severity + ": " + strconv.Itoa(n)
		if !strings.Contains(text, want) {
			t.Errorf("severity summary missing %q (real output has %d %s matches)", want, n, severity)
		}
	}

	// Real severities are capitalized ("High"); the summary must render them
	// lowercased to match the targetdb finding convention.
	if strings.Contains(text, "  - High: ") {
		t.Errorf("summary must lowercase severities:\n%s", text)
	}

	if !strings.Contains(text, "```json\n{") {
		t.Errorf("raw report not fenced as json:\n%s", text)
	}
}

// The upstream presenter golden carries the image-source shape (source.target
// as an object with userInput/imageID/layers) — describeSource must render it.
func TestVulnScanGolden_ImageSourceShape(t *testing.T) {
	stdout := loadGolden(t, "grype-image-scan-presenter-golden.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewVulnScanImage(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "user-input"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "user-input (image)") {
		t.Errorf("image source not rendered from target.userInput:\n%s", text)
	}
	if !strings.Contains(text, "**Matches:** 2") {
		t.Errorf("presenter golden has 2 matches, summary missing count:\n%s", text)
	}
	if !strings.Contains(text, "critical: 1") {
		t.Errorf("capitalized Critical not normalized to lowercase in summary:\n%s", text)
	}
}

// The severity filter is client-side; the fenced document and the summary
// must agree with it while the underlying scan ran unfiltered.
func TestVulnScanGolden_SeverityFilterAppliesToFencedJSON(t *testing.T) {
	stdout := loadGolden(t, "grype-sbom-scan.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewVulnScanImage(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest", "severity": "high"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text

	var doc struct {
		Matches []struct {
			Vulnerability struct {
				Severity string `json:"severity"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("fixture is not grype JSON: %v", err)
	}
	high := 0
	for _, m := range doc.Matches {
		if strings.EqualFold(m.Vulnerability.Severity, "high") {
			high++
		}
	}
	if high == 0 {
		t.Fatalf("fixture unexpectedly has no high-severity matches")
	}

	if !strings.Contains(text, "**Matches:** "+strconv.Itoa(high)) {
		t.Errorf("filtered summary must count only >= high matches (%d), got:\n%s", high, text)
	}
	if strings.Contains(text, "medium: ") {
		t.Errorf("filtered summary must not count medium matches:\n%s", text)
	}

	// The fenced JSON must contain the filtered document, extractable by the
	// campaign dataflow.
	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatalf("fenced JSON not extractable via workflow.StructuredFromText")
	}
	extracted := mustDecodeValue(t, raw)
	matches, ok := workflow.LookupPathValue(extracted, "matches")
	if !ok || matches == nil {
		t.Fatalf("record-rule path \"matches\" does not resolve in filtered output")
	}
	if arr, ok := matches.([]any); !ok || len(arr) != high {
		t.Errorf("filtered fenced JSON has %v matches, want %d", matches, high)
	}
}

// --- campaign chaining: record-rule paths against real shapes ---

// The recommended grype record rule (documented for the orchestrator):
//
//	{"type": "finding", "path": "matches", "fields": {
//	    "title":       "vulnerability.id",
//	    "severity":    "vulnerability.severity",
//	    "description": "vulnerability.description",
//	    "evidence":    "artifact.purl",
//	    "host":        "artifact.locations.0.path"
//	}}
//
// (host is a file path for image/dir scans; the recorder falls back to
// "unknown" when it is empty — omit it for image scans if preferred.)
func TestVulnScanGolden_RecordRuleFieldsResolveAgainstRealOutput(t *testing.T) {
	stdout := loadGolden(t, "grype-sbom-scan.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewVulnScanImage(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	raw, ok := workflow.StructuredFromText(result.Content[0].Text)
	if !ok {
		t.Fatalf("grype JSON not extractable from wrapper output (```json fence broken)")
	}
	value := mustDecodeValue(t, raw)

	matches, ok := workflow.LookupPathValue(value, "matches")
	if !ok {
		t.Fatalf("record-rule path \"matches\" does not resolve (record rules would record nothing)")
	}
	arr, ok := matches.([]any)
	if !ok {
		t.Fatalf("record-rule path \"matches\" is not an array: %T", matches)
	}
	if len(arr) == 0 {
		t.Fatalf("real fixture has no matches to map")
	}

	required := []string{
		"vulnerability.id",
		"vulnerability.severity",
		"vulnerability.description",
		"artifact.purl",
		"artifact.name",
		"artifact.version",
		"artifact.type",
		"artifact.locations.0.path",
		"vulnerability.fix.state",
	}
	for i, item := range arr {
		for _, path := range required {
			if _, ok := workflow.LookupPathValue(item, path); !ok {
				t.Errorf("matches.%d is missing path %q used by the recommended record rule", i, path)
			}
		}
	}
}

// The optional syft record rule for package inventory (targetdb has no
// package type; packages record as informational findings):
//
//	{"type": "finding", "path": "artifacts", "fields": {
//	    "title":       "name",
//	    "description": "type",
//	    "evidence":    "purl"
//	}}
func TestSbomGenerateGolden_RecordRuleFieldsResolveAgainstRealOutput(t *testing.T) {
	stdout := loadGolden(t, "syft-dir-sbom.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return stdout }
	tool := NewSbomGenerate(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "dir:/tmp/scan-target"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	raw, ok := workflow.StructuredFromText(result.Content[0].Text)
	if !ok {
		t.Fatalf("syft JSON not extractable from wrapper output (```json fence broken)")
	}
	value := mustDecodeValue(t, raw)

	artifacts, ok := workflow.LookupPathValue(value, "artifacts")
	if !ok {
		t.Fatalf("record-rule path \"artifacts\" does not resolve")
	}
	arr, ok := artifacts.([]any)
	if !ok {
		t.Fatalf("record-rule path \"artifacts\" is not an array: %T", artifacts)
	}
	if len(arr) == 0 {
		t.Fatalf("real fixture has no artifacts to map")
	}

	for i, item := range arr {
		for _, path := range []string{"name", "version", "type", "purl"} {
			if _, ok := workflow.LookupPathValue(item, path); !ok {
				t.Errorf("artifacts.%d is missing path %q used by the package record rule", i, path)
			}
		}
	}
}

// --- chain: sbom_generate output feeds vuln_scan_sbom ---

// The point of the toolset: the JSON sbom_generate returns is a valid grype
// sbom: input (verified end-to-end with the real binaries; see
// testdata/sbom/README.md). Here the fenced JSON from a generate result is
// written to disk and scanned by the sbom tool with the real grype output.
func TestGolden_GeneratedSbomFeedsVulnScanSbom(t *testing.T) {
	syftStdout := loadGolden(t, "syft-dir-sbom.json")
	grypeStdout := loadGolden(t, "grype-sbom-scan.json")

	genMock := executor.NewMock()
	genMock.StdoutFn = func(_ string, _ []string) []byte { return syftStdout }
	genResult, err := NewSbomGenerate(genMock).Execute(context.Background(), mustJSON(map[string]any{"source": "dir:/tmp/scan-target"}))
	if err != nil {
		t.Fatalf("sbom_generate Execute() returned error: %v", err)
	}

	// Extract exactly what the campaign dataflow would extract.
	sbomJSON, ok := workflow.StructuredFromText(genResult.Content[0].Text)
	if !ok {
		t.Fatalf("generated SBOM not extractable from sbom_generate output")
	}
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, sbomJSON, 0o644); err != nil {
		t.Fatalf("writing extracted SBOM: %v", err)
	}

	scanMock := executor.NewMock()
	scanMock.StdoutFn = func(_ string, _ []string) []byte { return grypeStdout }
	scanResult, err := NewVulnScanSbom(scanMock).Execute(context.Background(), mustJSON(map[string]any{"sbom_file": sbomPath, "fail_on": "high"}))
	if err != nil {
		t.Fatalf("vuln_scan_sbom Execute() returned error: %v", err)
	}
	if scanResult.IsError {
		t.Fatalf("unexpected error result: %s", scanResult.Content[0].Text)
	}

	text := scanResult.Content[0].Text
	if !strings.Contains(text, "```json\n{") {
		t.Errorf("scan result not fenced for campaign extraction:\n%s", text)
	}
	if _, ok := workflow.StructuredFromText(text); !ok {
		t.Errorf("scan result not extractable via workflow.StructuredFromText")
	}
}
