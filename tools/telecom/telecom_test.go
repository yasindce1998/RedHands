package telecom

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// allTools returns every tool in the telecom package instantiated with the
// given executor (unused by the HTTP-only tools). This is the single source
// of truth for enumerating tools.
func allTools(exec executor.Executor) []mcp.Tool {
	return []mcp.Tool{
		NewDoctor(exec),
		NewFirmwareAnalyze(exec),
		NewFirmwareExtract(exec),
		NewFirmwareDiff(exec),
		NewFirmwareNvDump(exec),
		NewSDRScan(exec),
		NewThreats(),
		NewAlerts(),
		NewStats(),
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---------------------------------------------------------------------------
// Test: All tools have non-empty Name() and Description() that mention
// StaticZero and the authorized-lab-use restriction.
// ---------------------------------------------------------------------------

func TestAllTools_NameAndDescription(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	if len(tools) == 0 {
		t.Fatal("allTools returned zero tools")
	}

	seen := make(map[string]bool)
	for _, tool := range tools {
		name := tool.Name()
		desc := tool.Description()

		if name == "" {
			t.Errorf("tool has empty Name()")
			continue
		}
		if !strings.HasPrefix(name, "telecom_") {
			t.Errorf("tool %q: Name() missing telecom_ prefix", name)
		}
		if desc == "" {
			t.Errorf("tool %q has empty Description()", name)
			continue
		}
		if !strings.Contains(desc, "StaticZero") {
			t.Errorf("tool %q: Description() must mention StaticZero", name)
		}
		if !strings.Contains(desc, "authorized lab use only") {
			t.Errorf("tool %q: Description() must mention authorized lab use only", name)
		}
		if seen[name] {
			t.Errorf("duplicate tool name: %q", name)
		}
		seen[name] = true
	}

	t.Logf("validated %d tools for Name/Description", len(tools))
}

// ---------------------------------------------------------------------------
// Test: All tools return valid JSON object schemas
// ---------------------------------------------------------------------------

func TestAllTools_InputSchemaValid(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tool := range tools {
		name := tool.Name()
		schema := tool.InputSchema()

		if len(schema) == 0 {
			t.Errorf("tool %q: InputSchema() returned empty", name)
			continue
		}

		var parsed map[string]any
		if err := json.Unmarshal(schema, &parsed); err != nil {
			t.Errorf("tool %q: InputSchema() is invalid JSON: %v", name, err)
			continue
		}
		if tp, ok := parsed["type"]; !ok || tp != "object" {
			t.Errorf("tool %q: InputSchema() missing \"type\": \"object\"", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Doctor tool
// ---------------------------------------------------------------------------

const doctorReportJSON = `{
  "checks": [
    {"name": "platform", "status": "pass", "detail": "Linux x86_64"},
    {"name": "kernel", "status": "pass", "detail": "6.6.0"}
  ],
  "modules": [
    {"module": 16, "program": "telecom_openat", "status": "available", "detail": "tracepoint syscalls/sys_enter_openat"}
  ]
}`

func TestDoctor_Execute_Default(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(doctorReportJSON)
	}
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, doctorReportJSON) {
		t.Errorf("expected DoctorReport JSON in result, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "read-only preflight") {
		t.Errorf("expected preflight header in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "staticzero-defense" {
		t.Errorf("expected binary staticzero-defense, got %q", call.Binary)
	}
	assertContains(t, call.Args, "--doctor")
	assertContains(t, call.Args, "--json")
}

func TestDoctor_Execute_WithFlags(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(doctorReportJSON)
	}
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"bpf_path":        "/opt/staticzero/staticzero-defense.bpf.o",
		"modem_path":      "/dev/cdc-wdm1",
		"modules":         []int{16, 17, 22},
		"allow_modem_pid": []int64{42, 1337},
		"all":             true,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--bpf-path", "/opt/staticzero/staticzero-defense.bpf.o")
	assertArgs(t, call.Args, "--modem-path", "/dev/cdc-wdm1")
	assertArgs(t, call.Args, "--modules", "16,17,22")
	assertArgs(t, call.Args, "--allow-modem-pid", "42,1337")
	assertContains(t, call.Args, "--all")
}

func TestDoctor_TelecomDetectExplicitFalse(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(doctorReportJSON)
	}
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"telecom_detect": false,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	assertContains(t, mock.LastCall().Args, "--telecom-detect=false")
}

func TestDoctor_PreflightFailedStillReturnsReport(t *testing.T) {
	// staticzero-defense --doctor exits nonzero when the preflight fails but
	// has already printed the DoctorReport JSON on stdout. The tool must
	// surface the report rather than swallowing it in an error.
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(doctorReportJSON)
	}
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("Error: defense preflight failed; use --doctor for details")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"exit status 1"}
	}
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("failed preflight should still return the report, got error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "PREFLIGHT FAILED") {
		t.Errorf("expected PREFLIGHT FAILED status in result, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, doctorReportJSON) {
		t.Errorf("expected DoctorReport JSON in result, got: %s", result.Content[0].Text)
	}
}

func TestDoctor_ExecuteError_NoStdout(t *testing.T) {
	mock := executor.NewMock()
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"binary not found"}
	}
	tool := NewDoctor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails without a report")
	}
	if !strings.Contains(result.Content[0].Text, "doctor failed") {
		t.Errorf("expected failure message, got: %s", result.Content[0].Text)
	}
}

func TestDoctor_InvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
	}{
		{"module_id_too_large", map[string]any{"modules": []int{256}}},
		{"module_id_negative", map[string]any{"modules": []int{-1}}},
		{"pid_zero", map[string]any{"allow_modem_pid": []int64{0}}},
		{"pid_too_large", map[string]any{"allow_modem_pid": []int64{4294967296}}},
		{"too_many_pids", map[string]any{"allow_modem_pid": []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33}}},
		{"bad_bpf_path", map[string]any{"bpf_path": "/tmp/x;rm -rf /"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewDoctor(executor.NewMock())
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Firmware tools
// ---------------------------------------------------------------------------

func tempFirmwareFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("\x7fELF fake modem image"), 0o600); err != nil {
		t.Fatalf("create temp firmware file: %v", err)
	}
	return path
}

func TestFirmwareAnalyze_Execute(t *testing.T) {
	dir := t.TempDir()
	target := tempFirmwareFile(t, "modem.mbn")
	report := filepath.Join(dir, "fw_analysis.json")
	if err := os.WriteFile(report, []byte(`{"firmware_path":"`+target+`","chipset":"Qualcomm","findings":[]}`), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Analyzing firmware...\nAnalysis complete: 0 findings\n")
	}
	tool := NewFirmwareAnalyze(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target":  target,
		"chipset": "qualcomm",
		"report":  report,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, `"chipset":"Qualcomm"`) {
		t.Errorf("expected report JSON contents in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "modem-firmware" {
		t.Errorf("expected binary modem-firmware, got %q", call.Binary)
	}
	if call.Args[0] != "analyze" {
		t.Errorf("expected subcommand analyze first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--target", target)
	assertArgs(t, call.Args, "--chipset", "qualcomm")
	assertArgs(t, call.Args, "--report", report)
}

func TestFirmwareAnalyze_FallsBackToStdout(t *testing.T) {
	target := tempFirmwareFile(t, "modem.mbn")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Analysis complete: 3 findings")
	}
	tool := NewFirmwareAnalyze(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target":  target,
		"chipset": "mediatek",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Analysis complete: 3 findings") {
		t.Errorf("expected stdout fallback in result, got: %s", result.Content[0].Text)
	}
}

func TestFirmwareExtract_Execute(t *testing.T) {
	dir := t.TempDir()
	image := tempFirmwareFile(t, "modem.mbn")
	outDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), []byte(`{"path":"modem.mbn","sections":[]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Extraction complete: 2 sections found")
	}
	tool := NewFirmwareExtract(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":   image,
		"output":  outDir,
		"chipset": "samsung-shannon",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, `"sections":[]`) {
		t.Errorf("expected manifest JSON in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Args[0] != "extract" {
		t.Errorf("expected subcommand extract first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--image", image)
	assertArgs(t, call.Args, "--output", outDir)
	assertArgs(t, call.Args, "--chipset", "samsung-shannon")
}

func TestFirmwareDiff_Execute(t *testing.T) {
	oldImg := tempFirmwareFile(t, "old.mbn")
	newImg := tempFirmwareFile(t, "new.mbn")

	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("3 differing regions found")
	}
	tool := NewFirmwareDiff(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"old":     oldImg,
		"new":     newImg,
		"chipset": "intel-xgold",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "3 differing regions found") {
		t.Errorf("expected diff output in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Args[0] != "diff" {
		t.Errorf("expected subcommand diff first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--old", oldImg)
	assertArgs(t, call.Args, "--new", newImg)
	assertArgs(t, call.Args, "--chipset", "intel-xgold")
}

func TestFirmwareNvDump_Execute(t *testing.T) {
	dir := t.TempDir()
	image := tempFirmwareFile(t, "nv.img")
	out := filepath.Join(dir, "nv_items.json")
	if err := os.WriteFile(out, []byte(`[{"id":10,"name":"NV_SEC_CODE_I"}]`), 0o600); err != nil {
		t.Fatalf("write nv output: %v", err)
	}

	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("NV dump written")
	}
	tool := NewFirmwareNvDump(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":  image,
		"output": out,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "NV_SEC_CODE_I") {
		t.Errorf("expected NV items JSON in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Args[0] != "nv-dump" {
		t.Errorf("expected subcommand nv-dump first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--image", image)
	assertArgs(t, call.Args, "--output", out)
}

func TestFirmware_MissingInputFile(t *testing.T) {
	tests := []struct {
		name   string
		tool   mcp.Tool
		params map[string]any
	}{
		{
			name: "analyze",
			tool: NewFirmwareAnalyze(executor.NewMock()),
			params: map[string]any{
				"target":  "/nonexistent/modem.mbn",
				"chipset": "qualcomm",
			},
		},
		{
			name: "extract",
			tool: NewFirmwareExtract(executor.NewMock()),
			params: map[string]any{
				"image":   "/nonexistent/modem.mbn",
				"chipset": "qualcomm",
			},
		},
		{
			name: "diff_old",
			tool: NewFirmwareDiff(executor.NewMock()),
			params: map[string]any{
				"old":     "/nonexistent/old.mbn",
				"new":     tempFirmwareFile(t, "new.mbn"),
				"chipset": "qualcomm",
			},
		},
		{
			name: "nv_dump",
			tool: NewFirmwareNvDump(executor.NewMock()),
			params: map[string]any{
				"image": "/nonexistent/nv.img",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected missing-file validation error")
			}
			if !strings.Contains(result.Content[0].Text, "not accessible") {
				t.Errorf("expected 'not accessible' message, got: %s", result.Content[0].Text)
			}
		})
	}
}

func TestFirmware_InvalidChipset(t *testing.T) {
	target := tempFirmwareFile(t, "modem.mbn")
	tool := NewFirmwareAnalyze(executor.NewMock())

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target":  target,
		"chipset": "broadcomm",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected chipset validation error")
	}
	if !strings.Contains(result.Content[0].Text, "invalid chipset") {
		t.Errorf("expected 'invalid chipset' message, got: %s", result.Content[0].Text)
	}
}

func TestFirmware_ChipsetAliases(t *testing.T) {
	// shannon / intel / balong are accepted by the Rust analyzer as aliases.
	for _, chipset := range []string{"shannon", "intel", "balong"} {
		t.Run(chipset, func(t *testing.T) {
			target := tempFirmwareFile(t, "modem.mbn")
			mock := executor.NewMock()
			tool := NewFirmwareAnalyze(mock)

			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
				"target":  target,
				"chipset": chipset,
			}))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if result.IsError {
				t.Errorf("expected alias %q to be accepted, got: %s", chipset, result.Content[0].Text)
			}
			assertArgs(t, mock.LastCall().Args, "--chipset", chipset)
		})
	}
}

func TestFirmware_ExecutorError(t *testing.T) {
	target := tempFirmwareFile(t, "modem.mbn")
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("Unsupported chipset: broadcomm")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution failed (exit 1)"}
	}
	tool := NewFirmwareAnalyze(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target":  target,
		"chipset": "qualcomm",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "Unsupported chipset") {
		t.Errorf("expected stderr in error, got: %s", result.Content[0].Text)
	}
}

func TestFirmware_InvalidJSON(t *testing.T) {
	tool := NewFirmwareAnalyze(executor.NewMock())
	result, err := tool.Execute(context.Background(), json.RawMessage(`not json at all`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for malformed JSON")
	}
	if !strings.Contains(result.Content[0].Text, "invalid input") {
		t.Errorf("expected 'invalid input' message, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Defense engine HTTP API tools
// ---------------------------------------------------------------------------

func TestAPI_Tools(t *testing.T) {
	tests := []struct {
		name     string
		tool     *defenseAPITool
		wantPath string
		body     string
	}{
		{
			name:     "threats",
			tool:     NewThreats(),
			wantPath: "/api/v1/threats",
			body:     `[{"threat_id":"T-1","severity":"critical","category":"imsi-catching"}]`,
		},
		{
			name:     "alerts",
			tool:     NewAlerts(),
			wantPath: "/api/v1/alerts",
			body:     `[{"timestamp_ns":1,"alert_type":"identity_request","severity":3}]`,
		},
		{
			name:     "stats",
			tool:     NewStats(),
			wantPath: "/api/v1/stats",
			body:     `{"uptime_seconds":42,"events_processed":100,"threats_detected":3}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			var gotMethod string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotMethod = r.Method
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			result, err := tc.tool.Execute(context.Background(), mustJSON(map[string]any{
				"base_url": srv.URL,
			}))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
			}
			if gotPath != tc.wantPath {
				t.Errorf("expected request path %q, got %q", tc.wantPath, gotPath)
			}
			if gotMethod != http.MethodGet {
				t.Errorf("expected GET, got %s", gotMethod)
			}
			if !strings.Contains(result.Content[0].Text, tc.body) {
				t.Errorf("expected response body in result, got: %s", result.Content[0].Text)
			}
		})
	}
}

func TestAPI_HTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "persistence disabled", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	tool := NewThreats()
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"base_url": srv.URL,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for HTTP 503")
	}
	if !strings.Contains(result.Content[0].Text, "503") {
		t.Errorf("expected status code in error, got: %s", result.Content[0].Text)
	}
}

func TestAPI_ConnectionFailed(t *testing.T) {
	// Bind then immediately close so the port refuses connections.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedURL := "http://" + listener.Addr().String()
	_ = listener.Close()

	tool := NewStats()
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"base_url": closedURL,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when the engine is unreachable")
	}
	if !strings.Contains(result.Content[0].Text, "request failed") {
		t.Errorf("expected request-failure message, got: %s", result.Content[0].Text)
	}
}

func TestAPI_NonLoopbackRejected(t *testing.T) {
	tool := NewThreats()

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"base_url": "http://10.0.0.5:9100",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected non-loopback base_url to be rejected")
	}
	if !strings.Contains(result.Content[0].Text, "loopback") {
		t.Errorf("expected loopback rejection message, got: %s", result.Content[0].Text)
	}

	// allow_remote=true bypasses the loopback restriction.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	result, err = tool.Execute(context.Background(), mustJSON(map[string]any{
		"base_url":     srv.URL,
		"allow_remote": true,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Errorf("expected allow_remote=true to be accepted, got: %s", result.Content[0].Text)
	}
}

func TestAPI_BadBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{"bad_scheme", "ftp://127.0.0.1:9100"},
		{"missing_host", "http://"},
		{"credentials", "http://user:pass@127.0.0.1:9100"},
		{"garbage", ":::not a url:::"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewAlerts()
			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
				"base_url": tc.baseURL,
			}))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected base_url %q to be rejected", tc.baseURL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SDR scan tool
// ---------------------------------------------------------------------------

func TestSDRScan_Execute_Defaults(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Scanning 60 EARFCNs for cells...\nScan complete: 0 cells found")
	}
	tool := NewSDRScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Scan complete: 0 cells found") {
		t.Errorf("expected scan output in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "sdr-bridge" {
		t.Errorf("expected binary sdr-bridge, got %q", call.Binary)
	}
	assertArgs(t, call.Args, "--mode", "scan")
	assertArgs(t, call.Args, "--sdr-type", "hackrf")
	assertArgs(t, call.Args, "--frequency", "2620000000")
	assertArgs(t, call.Args, "--sample-rate", "20000000")
	assertArgs(t, call.Args, "--gain", "40")
	assertArgs(t, call.Args, "--bandwidth", "20000000")
}

func TestSDRScan_Execute_WithParams(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Scan complete: 2 cells found")
	}
	tool := NewSDRScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"sdr_type":     "rtlsdr",
		"device_id":    "serial-42",
		"frequency_hz": 1805000000,
		"gain_db":      25,
		"scan_bands":   "100,2750,6150",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--sdr-type", "rtlsdr")
	assertArgs(t, call.Args, "--device-id", "serial-42")
	assertArgs(t, call.Args, "--frequency", "1805000000")
	assertArgs(t, call.Args, "--gain", "25")
	assertArgs(t, call.Args, "--scan-bands", "100,2750,6150")
}

func TestSDRScan_TimeoutWithOutputStillReturnsScan(t *testing.T) {
	// The bridge blocks in its control loop after the sweep; a timeout error
	// with captured scan output should still return the scan result.
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Scan complete: 1 cells found")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution cancelled or timed out: context deadline exceeded"}
	}
	tool := NewSDRScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("timeout with scan output should return the scan, got error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Scan complete: 1 cells found") {
		t.Errorf("expected scan output in result, got: %s", result.Content[0].Text)
	}
}

func TestSDRScan_InvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
	}{
		{"bad_sdr_type", map[string]any{"sdr_type": "usrp2"}},
		{"bad_scan_bands", map[string]any{"scan_bands": "all-lte;rm -rf /"}},
		{"non_numeric_scan_bands", map[string]any{"scan_bands": "abc,def"}},
		{"scan_bands_too_large", map[string]any{"scan_bands": "99999999999"}},
		{"frequency_too_high", map[string]any{"frequency_hz": 7000000000}},
		{"frequency_negative", map[string]any{"frequency_hz": -5}},
		{"sample_rate_too_high", map[string]any{"sample_rate_hz": 200000000}},
		{"gain_too_high", map[string]any{"gain_db": 500}},
		{"bad_device_id", map[string]any{"device_id": "id`id"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewSDRScan(executor.NewMock())
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestSDRScan_AllLTEAccepted(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSDRScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"scan_bands": "all-lte",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	assertArgs(t, mock.LastCall().Args, "--scan-bands", "all-lte")
}

// ---------------------------------------------------------------------------
// Test: Shell metacharacter injection is rejected
// ---------------------------------------------------------------------------

func TestShellMetacharRejection(t *testing.T) {
	forbiddenChars := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

	tests := []struct {
		name   string
		tool   mcp.Tool
		params func(injection string) json.RawMessage
	}{
		{
			name: "Doctor_bpf_path",
			tool: NewDoctor(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"bpf_path": "/opt/bpf.o" + inj + "rm -rf /"})
			},
		},
		{
			name: "Doctor_modem_path",
			tool: NewDoctor(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"modem_path": "/dev/cdc-wdm0" + inj + "x"})
			},
		},
		{
			name: "FirmwareAnalyze_target",
			tool: NewFirmwareAnalyze(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"target": "/tmp/modem.mbn" + inj + "x", "chipset": "qualcomm"})
			},
		},
		{
			name: "FirmwareAnalyze_report",
			tool: NewFirmwareAnalyze(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"target": tempFirmwareFile(t, "m.bin"), "chipset": "qualcomm", "report": "/tmp/r.json" + inj + "x"})
			},
		},
		{
			name: "FirmwareExtract_image",
			tool: NewFirmwareExtract(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"image": "/tmp/modem.mbn" + inj + "x", "chipset": "qualcomm"})
			},
		},
		{
			name: "FirmwareDiff_old",
			tool: NewFirmwareDiff(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"old": "/tmp/old.mbn" + inj + "x", "new": tempFirmwareFile(t, "n.bin"), "chipset": "qualcomm"})
			},
		},
		{
			name: "FirmwareNvDump_image",
			tool: NewFirmwareNvDump(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"image": "/tmp/nv.img" + inj + "x"})
			},
		},
		{
			name: "SDRScan_device_id",
			tool: NewSDRScan(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"device_id": "serial" + inj + "evil"})
			},
		},
		{
			name: "Threats_base_url",
			tool: NewThreats(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"base_url": "http://127.0.0.1:9100" + inj + "x"})
			},
		},
	}

	for _, tc := range tests {
		for _, char := range forbiddenChars {
			testName := tc.name + "_char_" + charLabel(char)
			t.Run(testName, func(t *testing.T) {
				params := tc.params(char)
				result, err := tc.tool.Execute(context.Background(), params)
				if err != nil {
					t.Fatalf("Execute returned Go error: %v", err)
				}
				if !result.IsError {
					t.Errorf("expected rejection for char %q, but got success", char)
					return
				}
				if !strings.Contains(result.Content[0].Text, "forbidden character") {
					t.Errorf("expected 'forbidden character' in error message, got: %s", result.Content[0].Text)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test: validateSafeString with oversized input
// ---------------------------------------------------------------------------

func TestValidateSafeString_TooLong(t *testing.T) {
	longInput := strings.Repeat("a", 4097)
	tool := NewDoctor(executor.NewMock())

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"bpf_path": longInput,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected rejection for input exceeding 4096 chars")
	}
	if !strings.Contains(result.Content[0].Text, "too long") {
		t.Errorf("expected 'too long' message, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: validateBaseURL unit behavior
// ---------------------------------------------------------------------------

func TestValidateBaseURL_Units(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		allowRemote bool
		wantErr     bool
	}{
		{"default", "", false, false},
		{"loopback_ipv4", "http://127.0.0.1:9100", false, false},
		{"loopback_alt_octet", "http://127.0.0.2:9100", false, false},
		{"loopback_ipv6", "http://[::1]:9100", false, false},
		{"localhost", "http://localhost:9100", false, false},
		{"https_loopback", "https://127.0.0.1:9100", false, false},
		{"remote_rejected", "http://10.0.0.5:9100", false, true},
		{"remote_allowed", "http://10.0.0.5:9100", true, false},
		{"bad_scheme", "ftp://127.0.0.1:9100", false, true},
		{"credentials", "http://u:p@127.0.0.1:9100", false, true},
		{"empty_host", "http://", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateBaseURL(tc.raw, tc.allowRemote)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q", tc.raw)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.raw, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type mockError struct {
	msg string
}

func (e *mockError) Error() string { return e.msg }

func assertArgs(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return
		}
	}
	t.Errorf("expected args to contain %q %q, got %v", flag, value, args)
}

func assertContains(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, a := range args {
		if a == flag {
			return
		}
	}
	t.Errorf("expected args to contain %q, got %v", flag, args)
}

// charLabel returns a readable label for metacharacters used in test names.
func charLabel(c string) string {
	labels := map[string]string{
		";":  "semicolon",
		"|":  "pipe",
		"&":  "ampersand",
		"`":  "backtick",
		"$":  "dollar",
		"(":  "lparen",
		")":  "rparen",
		"{":  "lbrace",
		"}":  "rbrace",
		"<":  "lt",
		">":  "gt",
		"!":  "bang",
		"'":  "squote",
		"\"": "dquote",
		"\\": "backslash",
		"\n": "newline",
		"\r": "carriage_return",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return c
}
