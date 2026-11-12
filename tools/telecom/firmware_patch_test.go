package telecom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// tempPatchSpec writes a patch specification file and returns its path.
func tempPatchSpec(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "patch.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write patch spec: %v", err)
	}
	return path
}

const validPatchSpec = `{
	"patches": [
		{"offset": 40, "original": [1, 2, 3], "replacement": [9, 9, 9], "description": "nop out check"}
	],
	"description": "lab test patch"
}`

func TestFirmwarePatch_Execute(t *testing.T) {
	dir := t.TempDir()
	image := tempFirmwareFile(t, "modem.mbn")
	patchfile := tempPatchSpec(t, validPatchSpec)
	output := filepath.Join(dir, "modem-patched.mbn")

	mock := executor.NewMock()
	// The real binary writes the patched image; simulate it so the tool's
	// output-size reporting can be verified.
	mock.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "--output" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("patched-bytes"), 0o600)
			}
		}
		return []byte("Applying 1 patches to firmware...\nPatched firmware written to: " + output)
	}
	tool := NewFirmwarePatch(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":     image,
		"patchfile": patchfile,
		"output":    output,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"HIGH IMPACT", "Patched firmware written to", "13 bytes"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in result, got:\n%s", want, text)
		}
	}

	call := mock.LastCall()
	if call.Binary != "modem-firmware" {
		t.Errorf("expected binary modem-firmware, got %q", call.Binary)
	}
	if call.Args[0] != "patch" {
		t.Errorf("expected subcommand patch first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--image", image)
	assertArgs(t, call.Args, "--patchfile", patchfile)
	assertArgs(t, call.Args, "--output", output)
}

func TestFirmwarePatch_OutputNotWrittenStillSucceeds(t *testing.T) {
	image := tempFirmwareFile(t, "modem.mbn")
	patchfile := tempPatchSpec(t, validPatchSpec)
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Patch 0 original bytes don't match at offset 0x28")
	}
	tool := NewFirmwarePatch(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"image":     image,
		"patchfile": patchfile,
		"output":    filepath.Join(t.TempDir(), "out.mbn"),
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "not readable after the run") {
		t.Errorf("expected missing-output note, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "original bytes don't match") {
		t.Errorf("expected patch log in result, got: %s", result.Content[0].Text)
	}
}

func TestFirmwarePatch_MissingInput(t *testing.T) {
	image := tempFirmwareFile(t, "modem.mbn")
	patchfile := tempPatchSpec(t, validPatchSpec)
	dir := t.TempDir()

	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{
			name:   "image missing",
			params: map[string]any{"image": "/nonexistent/modem.mbn", "patchfile": patchfile, "output": dir + "/out.mbn"},
			want:   "not accessible",
		},
		{
			name:   "patchfile missing",
			params: map[string]any{"image": image, "patchfile": "/nonexistent/patch.json", "output": dir + "/out.mbn"},
			want:   "not accessible",
		},
		{
			name:   "output missing",
			params: map[string]any{"image": image, "patchfile": patchfile},
			want:   "output is required",
		},
		{
			name:   "image is directory",
			params: map[string]any{"image": dir, "patchfile": patchfile, "output": dir + "/out.mbn"},
			want:   "must be a file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := NewFirmwarePatch(executor.NewMock()).Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

func TestFirmwarePatch_InvalidPatchSpec(t *testing.T) {
	image := tempFirmwareFile(t, "modem.mbn")
	dir := t.TempDir()

	cases := []struct {
		name     string
		spec     string
		want     string
	}{
		{"not json", "this is not json", "not valid JSON"},
		{"missing patches", `{"description":"no patches"}`, "missing required \"patches\""},
		{"patch missing offset", `{"patches":[{"original":[1],"replacement":[2],"description":"x"}]}`, "missing \"offset\""},
		{"patch missing original", `{"patches":[{"offset":0,"replacement":[2],"description":"x"}]}`, "missing \"original\""},
		{"patch missing replacement", `{"patches":[{"offset":0,"original":[1],"description":"x"}]}`, "missing \"replacement\""},
		{"byte out of range", `{"patches":[{"offset":0,"original":[300],"replacement":[2],"description":"x"}]}`, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patchfile := tempPatchSpec(t, tc.spec)
			result, err := NewFirmwarePatch(executor.NewMock()).Execute(context.Background(), mustJSON(map[string]any{
				"image":     image,
				"patchfile": patchfile,
				"output":    filepath.Join(dir, "out.mbn"),
			}))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

func TestFirmwarePatch_ExecutorError(t *testing.T) {
	image := tempFirmwareFile(t, "modem.mbn")
	patchfile := tempPatchSpec(t, validPatchSpec)
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("Failed to read: permission denied")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"exit status 1"}
	}

	result, err := NewFirmwarePatch(mock).Execute(context.Background(), mustJSON(map[string]any{
		"image":     image,
		"patchfile": patchfile,
		"output":    filepath.Join(t.TempDir(), "out.mbn"),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "permission denied") {
		t.Errorf("expected stderr in error, got: %s", result.Content[0].Text)
	}
}

func TestFirmwarePatch_MetacharInjection(t *testing.T) {
	image := tempFirmwareFile(t, "modem.mbn")
	patchfile := tempPatchSpec(t, validPatchSpec)
	dir := t.TempDir()
	tool := NewFirmwarePatch(executor.NewMock())

	fields := []struct {
		name   string
		params func(inj string) map[string]any
	}{
		{"image", func(inj string) map[string]any {
			return map[string]any{"image": "/tmp/modem.mbn" + inj + "x", "patchfile": patchfile, "output": dir + "/out.mbn"}
		}},
		{"patchfile", func(inj string) map[string]any {
			return map[string]any{"image": image, "patchfile": "/tmp/patch.json" + inj + "x", "output": dir + "/out.mbn"}
		}},
		{"output", func(inj string) map[string]any {
			return map[string]any{"image": image, "patchfile": patchfile, "output": dir + "/out.mbn" + inj + "x"}
		}},
	}
	for _, field := range fields {
		for _, char := range shellMetachars {
			t.Run(field.name+"_char_"+charLabel(char), func(t *testing.T) {
				result, err := tool.Execute(context.Background(), mustJSON(field.params(char)))
				if err != nil {
					t.Fatalf("Execute returned Go error: %v", err)
				}
				if !result.IsError {
					t.Errorf("expected rejection for metachar %q, but got success", char)
					return
				}
				if !strings.Contains(result.Content[0].Text, "forbidden character") {
					t.Errorf("expected forbidden-character error for %q, got: %s", char, result.Content[0].Text)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Firmware monitor tool
// ---------------------------------------------------------------------------

func TestFirmwareMonitor_Execute_Defaults(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Monitoring modem on /dev/diag (protocol: diag)")
	}
	tool := NewFirmwareMonitor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Monitoring modem on /dev/diag") {
		t.Errorf("expected monitor output in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "modem-firmware" {
		t.Errorf("expected binary modem-firmware, got %q", call.Binary)
	}
	if call.Args[0] != "monitor" {
		t.Errorf("expected subcommand monitor first, got %v", call.Args)
	}
	assertArgs(t, call.Args, "--device", "/dev/diag")
	assertArgs(t, call.Args, "--protocol", "diag")
}

func TestFirmwareMonitor_Execute_WithParams(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("QMI message received")
	}
	tool := NewFirmwareMonitor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"device":   "/dev/cdc-wdm0",
		"protocol": "qmi",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--device", "/dev/cdc-wdm0")
	assertArgs(t, call.Args, "--protocol", "qmi")
}

// The monitor blocks on ctrl_c; a timeout with captured output must still
// return the captured monitor stream (telecom_sdr_scan pattern).
func TestFirmwareMonitor_BlocksUntilTimeout(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("DIAG_LOG: 0x0001 something happened")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution cancelled or timed out: context deadline exceeded"}
	}
	tool := NewFirmwareMonitor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("timeout with monitor output should return the capture, got error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "executor timeout") {
		t.Errorf("expected timeout note in result, got: %s", text)
	}
	if !strings.Contains(text, "DIAG_LOG: 0x0001") {
		t.Errorf("expected captured monitor output in result, got: %s", text)
	}
}

func TestFirmwareMonitor_TimeoutWithoutOutput(t *testing.T) {
	mock := executor.NewMock()
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution cancelled or timed out: context deadline exceeded"}
	}
	tool := NewFirmwareMonitor(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when the monitor times out with no output")
	}
	if !strings.Contains(result.Content[0].Text, "modem-firmware failed") {
		t.Errorf("expected failure message, got: %s", result.Content[0].Text)
	}
}

func TestFirmwareMonitor_InvalidParams(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"bad protocol", map[string]any{"protocol": "qcdm"}, "invalid protocol"},
		{"bad json", nil, "invalid input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := NewFirmwareMonitor(executor.NewMock())
			var params json.RawMessage
			if tc.params == nil {
				params = json.RawMessage(`{invalid`)
			} else {
				params = mustJSON(tc.params)
			}
			result, err := tool.Execute(context.Background(), params)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

func TestFirmwareMonitor_MetacharInjection(t *testing.T) {
	tool := NewFirmwareMonitor(executor.NewMock())
	for _, char := range shellMetachars {
		t.Run("device_char_"+charLabel(char), func(t *testing.T) {
			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
				"device": "/dev/diag" + char + "evil",
			}))
			if err != nil {
				t.Fatalf("Execute returned Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected rejection for metachar %q, but got success", char)
				return
			}
			if !strings.Contains(result.Content[0].Text, "forbidden character") {
				t.Errorf("expected forbidden-character error for %q, got: %s", char, result.Content[0].Text)
			}
		})
	}
}
