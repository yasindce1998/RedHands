package telecom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// Golden pipeline tests against real staticzero-defense / modem-firmware
// stdout captured in testdata/telecom/ (see that directory's README for the
// exact commands). They verify the wrapper path — fixture stdout →
// exit-code handling → markdown rendering → json fencing — plus campaign
// structured extraction of the shapes the binaries actually emit.

// doctorCheck mirrors one check of the real DoctorReport.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Checks  []doctorCheck `json:"checks"`
	Modules []struct {
		Module      int    `json:"module"`
		Program     string `json:"program"`
		Description string `json:"description"`
		Status      string `json:"status"`
		Detail      string `json:"detail"`
	} `json:"modules"`
}

func loadTelecomFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "telecom", name))
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

// TestDoctorGolden_FailedPreflightIsAResult pins the real failure shape:
// `staticzero-defense --doctor --json` exits 1 when the preflight fails but
// has already printed the full DoctorReport JSON on stdout. The report is
// the answer, so the wrapper must render it as a normal result with a
// PREFLIGHT FAILED banner and a json-fenced body that campaign extraction
// can parse.
func TestDoctorGolden_FailedPreflightIsAResult(t *testing.T) {
	report := loadTelecomFixture(t, "doctor-report.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return report }
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("Error: defense preflight failed; use --doctor for details")
	}
	mock.ErrFn = func(_ string, _ []string) error { return &mockError{"execution failed (exit 1)"} }
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("a failed preflight with a DoctorReport on stdout must be a result, not an error: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "PREFLIGHT FAILED") {
		t.Errorf("failure banner missing:\n%s", text)
	}
	if !strings.Contains(text, "```json") {
		t.Errorf("DoctorReport not fenced as json:\n%s", text)
	}
	if !strings.Contains(text, "Error: defense preflight failed") {
		t.Errorf("real stderr not surfaced in the details block:\n%s", text)
	}

	// The rendered markdown must be campaign-extractable, and the paths a
	// playbook would use against a DoctorReport must resolve.
	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatal("campaign extractor could not pull the DoctorReport out of the wrapper markdown")
	}
	value := mustDecodeValue(t, raw)
	for _, path := range []string{
		"checks", "checks.0.name", "checks.0.status", "checks.0.detail",
		"modules", "modules.0.module", "modules.0.program", "modules.0.status",
	} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against the real DoctorReport shape", path)
		}
	}

	// Cross-check the rendered report against the fixture content itself.
	var dr doctorReport
	if err := json.Unmarshal(report, &dr); err != nil {
		t.Fatalf("fixture is not a DoctorReport object (shape drift?): %v", err)
	}
	if len(dr.Checks) == 0 || len(dr.Modules) == 0 {
		t.Fatalf("fixture unexpectedly empty: %d checks, %d modules", len(dr.Checks), len(dr.Modules))
	}
	statuses := map[string]string{}
	for _, c := range dr.Checks {
		statuses[c.Name] = c.Status
	}
	// This capture was taken without root: the privileges check fails while
	// platform/kernel/ebpf_object pass. That mixed outcome is the real
	// failure shape, not an all-or-nothing report.
	if statuses["privileges"] != "fail" {
		t.Errorf("expected the real no-root capture to fail the privileges check, got %+v", statuses)
	}
	if statuses["platform"] != "pass" || statuses["kernel"] != "pass" {
		t.Errorf("expected platform/kernel checks to pass in the real capture, got %+v", statuses)
	}
	for _, c := range dr.Checks {
		if !strings.Contains(text, c.Name) {
			t.Errorf("check %q missing from rendered report", c.Name)
		}
	}
}

// TestDoctorGolden_AllModulesFlagAndModulePaths runs the doctor with the
// --all group flag against the real 40-module capture and verifies both the
// CLI arg and the module paths in the extracted report.
func TestDoctorGolden_AllModulesFlagAndModulePaths(t *testing.T) {
	report := loadTelecomFixture(t, "doctor-report-all-modules.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return report }
	mock.ErrFn = func(_ string, _ []string) error { return &mockError{"execution failed (exit 1)"} }
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"all": true}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("failed preflight with report must be a result: %s", result.Content[0].Text)
	}
	assertArgs(t, mock.LastCall().Args, "--json", "--all")

	var dr doctorReport
	if err := json.Unmarshal(report, &dr); err != nil {
		t.Fatalf("decoding all-modules fixture: %v", err)
	}
	if len(dr.Modules) != 40 {
		t.Errorf("expected the real --all capture to list 40 modules, got %d", len(dr.Modules))
	}

	raw, ok := workflow.StructuredFromText(result.Content[0].Text)
	if !ok {
		t.Fatal("campaign extractor could not pull the DoctorReport out of the wrapper markdown")
	}
	value := mustDecodeValue(t, raw)
	for _, path := range []string{"modules.39.module", "modules.39.program", "modules.39.status"} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against the real --all DoctorReport", path)
		}
	}
}

// TestFirmwareGolden_AnalysisReportIsFencedAndExtractable runs
// telecom_firmware_analyze with the real modem-firmware report written to
// the --report path (exactly what the binary does) and verifies the wrapper
// embeds it as json and that its finding paths resolve.
func TestFirmwareGolden_AnalysisReportIsFencedAndExtractable(t *testing.T) {
	report := loadTelecomFixture(t, "firmware-analysis.json")
	dir := t.TempDir()
	target := filepath.Join(dir, "synthetic-modem.bin")
	reportPath := filepath.Join(dir, "fw_analysis.json")
	if err := os.WriteFile(target, []byte("synthetic modem image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, report, 0o600); err != nil {
		t.Fatal(err)
	}

	mock := executor.NewMock()
	// The real analyzer logs progress lines to stdout and writes the report
	// to the --report path; replay the captured stdout too.
	mock.StdoutFn = func(_ string, _ []string) []byte { return loadTelecomFixture(t, "firmware-analyze-stdout.txt") }
	tool := NewFirmwareAnalyze(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target":  target,
		"chipset": "qualcomm",
		"report":  reportPath,
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("analysis must be a result: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "### Vulnerability report") {
		t.Errorf("report section missing:\n%s", text)
	}
	if !strings.Contains(text, "```json") {
		t.Errorf("vulnerability report not fenced as json:\n%s", text)
	}

	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatal("campaign extractor could not pull the vulnerability report out of the wrapper markdown")
	}
	value := mustDecodeValue(t, raw)
	for _, path := range []string{
		"firmware_path", "chipset",
		"findings", "findings.0.severity", "findings.0.category", "findings.0.title", "findings.0.offset",
		"attack_surfaces", "attack_surfaces.0.interface", "attack_surfaces.0.protocol",
		"protocol_handlers", "protocol_handlers.0.protocol", "protocol_handlers.0.message_types",
		"nv_items_of_interest", "nv_items_of_interest.0.id",
	} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against the real modem-firmware analysis report", path)
		}
	}

	// The real analyzer emits capitalized severities ("High", "Medium",
	// "Info"); the wrapper normalizes them to lowercase when embedding the
	// report, so consumers (campaign record rules, targetdb findings via
	// the recorder, direct readers of the tool result) get consistent
	// lowercase values.
	findingList, ok := workflow.LookupPathValue(value, "findings")
	if !ok {
		t.Fatal("findings missing")
	}
	findings, ok := findingList.([]any)
	if !ok {
		t.Fatalf("\"findings\" is not an array: %T", findingList)
	}
	if len(findings) == 0 {
		t.Fatal("real modem-firmware capture unexpectedly has no findings")
	}
	for i, finding := range findings {
		sev, ok := workflow.LookupPathValue(finding, "severity")
		if !ok {
			t.Fatalf("findings.%d.severity missing", i)
		}
		if s := workflow.ValueToString(sev); s != strings.ToLower(s) {
			t.Errorf("findings.%d severity %q must be normalized to lowercase by the wrapper", i, s)
		}
	}
}
