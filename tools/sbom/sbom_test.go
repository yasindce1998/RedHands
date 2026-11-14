package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- helpers ---

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// exitCodeExecutor mimics pkg/executor.BinaryExecutor's behavior for non-zero
// exits: it returns a Result carrying the exit code and captured output
// together with an error formatted exactly like the real executor's
// ("execution failed (exit N): ..."). The stock MockExecutor cannot simulate
// non-zero exit codes, and pkg/executor must not be modified.
type exitCodeExecutor struct {
	mu       sync.Mutex
	calls    []executor.MockCall
	stdout   string
	stderr   string
	exitCode int
}

func (e *exitCodeExecutor) Run(_ context.Context, binary string, args ...string) (*executor.Result, error) {
	e.mu.Lock()
	e.calls = append(e.calls, executor.MockCall{Binary: binary, Args: args})
	e.mu.Unlock()

	result := &executor.Result{
		Stdout:   []byte(e.stdout),
		Stderr:   []byte(e.stderr),
		ExitCode: e.exitCode,
	}
	if e.exitCode != 0 {
		return result, fmt.Errorf("execution failed (exit %d): exit status %d", e.exitCode, e.exitCode)
	}
	return result, nil
}

// --- sbom_generate: exact args ---

func TestSbomGenerate_DefaultArgsAreSyftJSONOnStdout(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSbomGenerate(mock)

	if _, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "dir:/data"})); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	call := mock.LastCall()
	if call.Binary != "syft" {
		t.Errorf("binary = %q, want syft", call.Binary)
	}
	want := []string{"dir:/data", "-o", "syft-json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestSbomGenerate_AllOptions(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSbomGenerate(mock)

	params := map[string]any{
		"source":            "alpine:latest",
		"format":            "cyclonedx-json",
		"output_file":       "/tmp/sbom.json",
		"select_catalogers": "+python,-rpm",
	}
	if _, err := tool.Execute(context.Background(), mustJSON(params)); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	call := mock.LastCall()
	want := []string{
		"alpine:latest",
		"-o", "cyclonedx-json", // stdout capture (chainable)
		"-o", "cyclonedx-json=/tmp/sbom.json", // file copy
		"--select-catalogers", "+python,-rpm",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

// --- vuln_scan_image / vuln_scan_sbom: exact args ---

func TestVulnScanImage_DefaultArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewVulnScanImage(mock)

	if _, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest"})); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	call := mock.LastCall()
	if call.Binary != "grype" {
		t.Errorf("binary = %q, want grype", call.Binary)
	}
	want := []string{"alpine:latest", "-o", "json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestVulnScanImage_AllOptions(t *testing.T) {
	mock := executor.NewMock()
	tool := NewVulnScanImage(mock)

	params := map[string]any{
		"source":      "registry:example.com/app:1.0",
		"only_fixed":  true,
		"fail_on":     "high",
		"output_file": "/tmp/grype.json",
	}
	if _, err := tool.Execute(context.Background(), mustJSON(params)); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	call := mock.LastCall()
	want := []string{
		"registry:example.com/app:1.0",
		"-o", "json",
		"-o", "json=/tmp/grype.json",
		"--only-fixed",
		"--fail-on", "high",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestVulnScanSbom_ArgsUseSbomScheme(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"artifacts":[]}`), 0o644); err != nil {
		t.Fatalf("writing temp SBOM: %v", err)
	}

	mock := executor.NewMock()
	tool := NewVulnScanSbom(mock)

	if _, err := tool.Execute(context.Background(), mustJSON(map[string]any{"sbom_file": sbomPath})); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	call := mock.LastCall()
	if call.Binary != "grype" {
		t.Errorf("binary = %q, want grype", call.Binary)
	}
	want := []string{"sbom:" + sbomPath, "-o", "json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

// --- grype exit-code semantics ---

// grype exits 2 when --fail-on is set and matches at/above the threshold are
// found (verified against the real grype v0.121.3 binary: the full JSON
// report is still written to stdout). That must surface as a result.
func TestVulnScanImage_ExitTwoIsAResultNotAnError(t *testing.T) {
	exec := &exitCodeExecutor{stdout: `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High"},"artifact":{"name":"a","version":"1"}}],"source":{"type":"directory","target":"/x"},"distro":{},"descriptor":{}}`, exitCode: 2}
	tool := NewVulnScanImage(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest", "fail_on": "high"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("threshold-exceeding findings (grype exit 2) must be a result, not an error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "VULNERABILITIES AT/ABOVE --fail-on high THRESHOLD") {
		t.Errorf("threshold banner missing:\n%s", text)
	}
	if !strings.Contains(text, "```json") {
		t.Errorf("report not fenced as json despite exit 2:\n%s", text)
	}
}

// grype exits 1 for real failures (bad source, DB load error): those stay errors.
func TestVulnScanImage_ExitOneIsAnError(t *testing.T) {
	exec := &exitCodeExecutor{stdout: "", stderr: "1 error occurred:\n * failed to load DB", exitCode: 1}
	tool := NewVulnScanImage(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest", "fail_on": "high"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("grype exit 1 (real failure) must be an error, got result:\n%s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "failed to load DB") {
		t.Errorf("stderr not surfaced in error:\n%s", result.Content[0].Text)
	}
}

// Without --fail-on, exit 2 cannot legitimately occur (grype maps exactly
// one error to it). Like barzakh's detection exit, it is still surfaced as a
// result — with a banner flagging the anomaly — rather than dropped.
func TestVulnScanImage_ExitTwoWithoutFailOnSurfacesAnomaly(t *testing.T) {
	exec := &exitCodeExecutor{exitCode: 2}
	tool := NewVulnScanImage(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"source": "alpine:latest"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("exit 2 must stay a result (single-producer exit code), got error:\n%s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "without --fail-on requested") {
		t.Fatalf("anomalous exit 2 without --fail-on not flagged:\n%s", result.Content[0].Text)
	}
}

func TestVulnScanSbom_ExitTwoIsAResultNotAnError(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"artifacts":[]}`), 0o644); err != nil {
		t.Fatalf("writing temp SBOM: %v", err)
	}
	exec := &exitCodeExecutor{stdout: `{"matches":[{"vulnerability":{"id":"CVE-1","severity":"Critical"},"artifact":{"name":"a","version":"1"}}],"source":{"type":"directory","target":"/x"},"distro":{},"descriptor":{}}`, exitCode: 2}
	tool := NewVulnScanSbom(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"sbom_file": sbomPath, "fail_on": "critical"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("threshold-exceeding findings (grype exit 2) must be a result, not an error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "VULNERABILITIES AT/ABOVE --fail-on critical THRESHOLD") {
		t.Errorf("threshold banner missing:\n%s", result.Content[0].Text)
	}
}

// --- validation tables ---

func TestSbomGenerate_ValidationTable(t *testing.T) {
	tool := NewSbomGenerate(executor.NewMock())

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"missing source", map[string]any{}, "source is required"},
		{"empty source", map[string]any{"source": ""}, "source is required"},
		{"semicolon", map[string]any{"source": "alpine;rm -rf"}, "forbidden character"},
		{"backtick", map[string]any{"source": "alpine`id`"}, "forbidden character"},
		{"dollar", map[string]any{"source": "$(id)"}, "forbidden character"},
		{"pipe", map[string]any{"source": "a|b"}, "forbidden character"},
		{"bad format", map[string]any{"source": "alpine:latest", "format": "xml"}, "format must be one of"},
		{"output_file metachar", map[string]any{"source": "alpine:latest", "output_file": "/tmp/a;b"}, "forbidden character"},
		{"catalogers metachar", map[string]any{"source": "alpine:latest", "select_catalogers": "+a;rm"}, "forbidden character"},
		{"catalogers too long", map[string]any{"source": "alpine:latest", "select_catalogers": strings.Repeat("a", 501)}, "too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error result, got:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Fatalf("error %q does not contain %q", result.Content[0].Text, tc.want)
			}
		})
	}
}

func TestVulnScanImage_ValidationTable(t *testing.T) {
	tool := NewVulnScanImage(executor.NewMock())

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"missing source", map[string]any{}, "source is required"},
		{"source metachar", map[string]any{"source": "a && b"}, "forbidden character"},
		{"bad severity", map[string]any{"source": "alpine:latest", "severity": "extreme"}, "severity must be one of"},
		{"bad fail_on", map[string]any{"source": "alpine:latest", "fail_on": "severe"}, "fail_on must be one of"},
		{"output_file metachar", map[string]any{"source": "alpine:latest", "output_file": "/tmp/x|y"}, "forbidden character"},
		{"bad json", nil, "invalid input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var params json.RawMessage
			if tc.params == nil {
				params = json.RawMessage(`{not json`)
			} else {
				params = mustJSON(tc.params)
			}
			result, err := tool.Execute(context.Background(), params)
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error result, got:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Fatalf("error %q does not contain %q", result.Content[0].Text, tc.want)
			}
		})
	}
}

func TestVulnScanSbom_FileMustExist(t *testing.T) {
	tool := NewVulnScanSbom(executor.NewMock())

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"missing sbom_file", map[string]any{}, "sbom_file is required"},
		{"nonexistent file", map[string]any{"sbom_file": "/nonexistent/sbom.json"}, "not accessible"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error result, got:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Fatalf("error %q does not contain %q", result.Content[0].Text, tc.want)
			}
		})
	}

	dir := t.TempDir()
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"sbom_file": dir}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "is a directory") {
		t.Fatalf("directory as sbom_file must be rejected, got:\n%s", result.Content[0].Text)
	}
}

// --- schema validity ---

func TestInputSchemasAreValidJSONObjects(t *testing.T) {
	tools := []struct {
		tool     mcp.Tool
		required string
	}{
		{NewSbomGenerate(executor.NewMock()), "source"},
		{NewVulnScanImage(executor.NewMock()), "source"},
		{NewVulnScanSbom(executor.NewMock()), "sbom_file"},
	}
	for _, tc := range tools {
		t.Run(tc.tool.Name(), func(t *testing.T) {
			var schema struct {
				Type       string                 `json:"type"`
				Properties map[string]any         `json:"properties"`
				Required   []string               `json:"required"`
				Extra      map[string]interface{} `json:"-"`
			}
			if err := json.Unmarshal(tc.tool.InputSchema(), &schema); err != nil {
				t.Fatalf("schema is not valid JSON: %v", err)
			}
			if schema.Type != "object" {
				t.Errorf("schema type = %q, want object", schema.Type)
			}
			found := false
			for _, r := range schema.Required {
				if r == tc.required {
					found = true
				}
			}
			if !found {
				t.Errorf("schema required %v does not contain %q", schema.Required, tc.required)
			}
			if _, ok := schema.Properties[tc.required]; !ok {
				t.Errorf("schema properties missing %q", tc.required)
			}
		})
	}
}

func TestSchemaEnums(t *testing.T) {
	var genSchema struct {
		Properties struct {
			Format struct {
				Enum []string `json:"enum"`
			} `json:"format"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(NewSbomGenerate(executor.NewMock()).InputSchema(), &genSchema); err != nil {
		t.Fatalf("parsing sbom_generate schema: %v", err)
	}
	if !reflect.DeepEqual(genSchema.Properties.Format.Enum, []string{"syft-json", "cyclonedx-json", "spdx-json"}) {
		t.Errorf("format enum = %v", genSchema.Properties.Format.Enum)
	}

	var scanSchema struct {
		Properties struct {
			FailOn struct {
				Enum []string `json:"enum"`
			} `json:"fail_on"`
			Severity struct {
				Enum []string `json:"enum"`
			} `json:"severity"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(NewVulnScanImage(executor.NewMock()).InputSchema(), &scanSchema); err != nil {
		t.Fatalf("parsing vuln_scan_image schema: %v", err)
	}
	want := []string{"negligible", "low", "medium", "high", "critical"}
	if !reflect.DeepEqual(scanSchema.Properties.FailOn.Enum, want) {
		t.Errorf("fail_on enum = %v, want %v", scanSchema.Properties.FailOn.Enum, want)
	}
	if !reflect.DeepEqual(scanSchema.Properties.Severity.Enum, want) {
		t.Errorf("severity enum = %v, want %v", scanSchema.Properties.Severity.Enum, want)
	}
}

// --- tool names (registration contract) ---

func TestToolNames(t *testing.T) {
	cases := map[string]mcp.Tool{
		"sbom_generate":   NewSbomGenerate(executor.NewMock()),
		"vuln_scan_image": NewVulnScanImage(executor.NewMock()),
		"vuln_scan_sbom":  NewVulnScanSbom(executor.NewMock()),
	}
	for wantName, tool := range cases {
		if tool.Name() != wantName {
			t.Errorf("Name() = %q, want %q", tool.Name(), wantName)
		}
		if tool.Description() == "" {
			t.Errorf("%s has empty description", wantName)
		}
	}
}
