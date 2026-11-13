package barzakh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/workflow"
)

// Golden pipeline tests against real barzakh-scanner stdout captured in
// testdata/barzakh/ (see that directory's README for the exact commands and
// the scanner output-shape history). They verify the full wrapper path —
// fixture stdout → exit-code handling → markdown formatting → severity
// summary — plus campaign structured extraction of the shape the binary
// actually emits.

// goldenScanResult mirrors the barzakh-scanner 0.7.0 ScanResult envelope:
// findings live under the "findings" key alongside "summary" and "risk".
type goldenScanResult struct {
	Status   string `json:"status"`
	Summary struct {
		TotalFindings   int  `json:"total_findings"`
		CriticalCount   int  `json:"critical_count"`
		HighCount       int  `json:"high_count"`
		MediumCount     int  `json:"medium_count"`
		LowCount        int  `json:"low_count"`
		InfoCount       int  `json:"info_count"`
		BootkitDetected bool `json:"bootkit_detected"`
	} `json:"summary"`
	Findings []goldenFinding `json:"findings"`
	Risk     struct {
		Score int    `json:"score"`
		Level string `json:"level"`
	} `json:"risk"`
}

// goldenFinding mirrors one element of the scanner's findings array.
type goldenFinding struct {
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// goldenExecutor (an alias of the exitCodeExecutor in barzakh_test.go) replays
// a recorded stdout with a recorded exit code, mimicking
// pkg/executor.BinaryExecutor's error contract for non-zero exits.
type goldenExecutor = exitCodeExecutor

func loadGolden(t *testing.T, parts ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return string(data)
}

func mustDecodeGolden(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("decoding fixture JSON: %v", err)
	}
	return value
}

func TestScanGolden_MaliciousDetectionSummaryMatchesRealOutput(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "scan-malicious-blacklotus.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 1}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/corpus/malicious_blacklotus_mok.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("real detection (exit 1) must be a result, not an error: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "BOOTKIT DETECTED") {
		t.Errorf("detection banner missing:\n%s", text)
	}

	// Recompute the expected severity counts from the fixture itself so the
	// assertion tracks the real scanner output, not a hand-written copy.
	var scan goldenScanResult
	if err := json.Unmarshal([]byte(stdout), &scan); err != nil {
		t.Fatalf("fixture is not the 0.7.0 ScanResult envelope (shape drift?): %v", err)
	}
	if len(scan.Findings) == 0 || !scan.Summary.BootkitDetected {
		t.Fatalf("malicious fixture unexpectedly clean: %+v", scan.Summary)
	}
	counts := map[string]int{}
	for _, f := range scan.Findings {
		counts[f.Severity]++
	}
	for severity, n := range counts {
		want := severity + ": " + strconv.Itoa(n)
		if !strings.Contains(text, want) {
			t.Errorf("severity summary missing %q (real output has %d %s findings)", want, n, severity)
		}
	}
	if !strings.Contains(text, "**Findings:** "+strconv.Itoa(len(scan.Findings))) {
		t.Errorf("total findings count missing from summary:\n%s", text)
	}

	// The raw ScanResult JSON must be passed through inside a ```json fence
	// so campaign extraction (workflow.StructuredFromText) can reach it.
	if !strings.Contains(text, "```json\n{") {
		t.Errorf("raw scan result not fenced as json:\n%s", text)
	}
}

func TestScanGolden_CleanScanSummarizesRealOutput(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "scan-clean-blacklotus.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 0}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/corpus/clean_blacklotus_mok.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("clean scan must not be an error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "no bootkit indicators detected") {
		t.Errorf("clean scan banner missing:\n%s", result.Content[0].Text)
	}
	// Even the clean corpus sample produces findings in the real output; the
	// summary must render counts for them.
	var scan goldenScanResult
	if err := json.Unmarshal([]byte(stdout), &scan); err != nil {
		t.Fatalf("fixture is not the 0.7.0 ScanResult envelope: %v", err)
	}
	if scan.Summary.BootkitDetected {
		t.Errorf("clean fixture claims bootkit_detected=true: %+v", scan.Summary)
	}
	if len(scan.Findings) > 0 && !strings.Contains(result.Content[0].Text, "**Findings:** "+strconv.Itoa(len(scan.Findings))) {
		t.Errorf("findings summary missing for clean scan:\n%s", result.Content[0].Text)
	}
}

// TestScanGolden_CampaignExtractionResolvesRealShape verifies that the
// markdown the wrapper emits is extractable by the campaign engine and that
// the paths a playbook would use against a 0.7.0 ScanResult resolve:
// findings array, per-finding fields, summary counts, and risk score.
func TestScanGolden_CampaignExtractionResolvesRealShape(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "scan-malicious-blacklotus.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 1}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	raw, ok := workflow.StructuredFromText(result.Content[0].Text)
	if !ok {
		t.Fatal("campaign extractor could not pull JSON out of the real scan result markdown")
	}
	var scan goldenScanResult
	if err := json.Unmarshal(raw, &scan); err != nil {
		t.Fatalf("extracted structured output is not the scanner ScanResult: %v", err)
	}
	if len(scan.Findings) == 0 {
		t.Fatal("extracted findings array is empty")
	}
	value := mustDecodeGolden(t, raw)
	for _, path := range []string{
		"status",
		"findings",
		"findings.0.detector",
		"findings.0.severity",
		"findings.0.title",
		"findings.0.confidence",
		"summary.total_findings",
		"summary.critical_count",
		"summary.bootkit_detected",
		"risk.score",
		"risk.level",
		"detector_runs",
		"scan_info.target",
	} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against real 0.7.0 scanner output", path)
		}
	}
}

// TestScanGolden_LegacyArrayShapeStillSummarizes pins the historical output
// shape: barzakh-scanner <= 0.6 emitted a bare top-level findings array with
// no envelope (real capture from a 0.5.0 release binary in
// testdata/barzakh/scan-malicious-blacklotus-v05.json). The wrapper must
// still summarize that shape so environments pinned to an older scanner do
// not silently lose the severity summary.
func TestScanGolden_LegacyArrayShapeStillSummarizes(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "scan-malicious-blacklotus-v05.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 1}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("legacy detection (exit 1) must be a result: %s", result.Content[0].Text)
	}
	var findings []goldenFinding
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("legacy fixture is not a top-level findings array: %v", err)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "**Findings:** "+strconv.Itoa(len(findings))) {
		t.Errorf("legacy array output not summarized:\n%s", text)
	}
	if _, enveloped := workflow.LookupPathValue(mustDecodeGolden(t, []byte(stdout)), "findings"); enveloped {
		t.Errorf("legacy fixture unexpectedly carries a findings envelope; shape history changed")
	}
}

func TestScenarioGolden_RunChainJSONIsExtractable(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "scenario-run-blacklotus-chain.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 0}
	tool := NewScenario(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "run", "name": "blacklotus-chain", "json": true}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("fully detected chain must be a result: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "chain fully detected") {
		t.Errorf("chain result banner missing:\n%s", text)
	}
	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatal("scenario run JSON not extractable from wrapper markdown")
	}
	value := mustDecodeGolden(t, raw)
	for _, path := range []string{"name", "chain_validated", "stages", "stages.0.payload", "stages.0.detected", "stages.0.detected_by", "stages.0.risk_score"} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against real scenario run output", path)
		}
	}
}

func TestValidateGolden_CorpusReportIsExtractable(t *testing.T) {
	stdout := loadGolden(t, "barzakh", "adversary-validate.json")
	exec := &goldenExecutor{stdout: stdout, exitCode: 0}
	tool := NewValidate(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"corpus": "/corpus", "json": true}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("corpus validation must be a result: %s", result.Content[0].Text)
	}
	raw, ok := workflow.StructuredFromText(result.Content[0].Text)
	if !ok {
		t.Fatal("corpus validation JSON not extractable from wrapper markdown")
	}
	value := mustDecodeGolden(t, raw)
	for _, path := range []string{"results", "total_payloads", "detected_count", "missed_count", "true_positive_rate", "false_positives", "true_negatives", "false_positive_rate", "results.0.payload_name", "results.0.detected", "results.0.matched_findings"} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against real adversary validate output", path)
		}
	}
}
