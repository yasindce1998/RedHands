package barzakh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- helpers ---

// writeTempFile creates a real file under t's temp dir so tools that verify
// input existence (inject input, esp payload, ml model, ...) can run against
// the MockExecutor.
func writeTempFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test-data"), 0o600); err != nil {
		t.Fatalf("creating temp file %s: %v", path, err)
	}
	return path
}

// newToolSpec mirrors toolFactory in barzakh_test.go for the capability-gap
// tools. params is a function (not a fixed map) because several tools verify
// that input paths exist, which requires real temp files per test run.
type newToolSpec struct {
	name    string
	newTool func(executor.Executor) mcp.Tool
	params  func(t *testing.T) map[string]any
}

var newTools = []newToolSpec{
	{
		name:    "barzakh_inject",
		newTool: func(e executor.Executor) mcp.Tool { return NewInject(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{
				"input":   writeTempFile(t, "fw.bin"),
				"output":  filepath.Join(t.TempDir(), "implanted.bin"),
				"payload": "trampoline",
			}
		},
	},
	{
		name:    "barzakh_esp_build",
		newTool: func(e executor.Executor) mcp.Tool { return NewEspBuild(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{
				"payload":  writeTempFile(t, "payload.bin"),
				"output":   filepath.Join(t.TempDir(), "esp.img"),
				"bootable": true,
			}
		},
	},
	{
		name:    "barzakh_qemu",
		newTool: func(e executor.Executor) mcp.Tool { return NewQemu(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{
				"action": "run",
				"esp":    writeTempFile(t, "esp.img"),
			}
		},
	},
	{
		name:    "barzakh_range",
		newTool: func(e executor.Executor) mcp.Tool { return NewRange(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{"action": "up", "suite": "ring-2"}
		},
	},
	{
		name:    "barzakh_fuzz",
		newTool: func(e executor.Executor) mcp.Tool { return NewFuzz(e) },
		params:  func(t *testing.T) map[string]any { return map[string]any{} },
	},
	{
		name:    "barzakh_history",
		newTool: func(e executor.Executor) mcp.Tool { return NewHistory(e) },
		params:  func(t *testing.T) map[string]any { return map[string]any{"action": "trends"} },
	},
	{
		name:    "barzakh_kb",
		newTool: func(e executor.Executor) mcp.Tool { return NewKb(e) },
		params:  func(t *testing.T) map[string]any { return map[string]any{"action": "list"} },
	},
	{
		name:    "barzakh_ml",
		newTool: func(e executor.Executor) mcp.Tool { return NewMl(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{"action": "train", "corpus": t.TempDir()}
		},
	},
	{
		name:    "barzakh_manifest_validate",
		newTool: func(e executor.Executor) mcp.Tool { return NewManifestValidate(e) },
		params: func(t *testing.T) map[string]any {
			return map[string]any{
				"corpus":   t.TempDir(),
				"manifest": writeTempFile(t, "corpus.toml"),
			}
		},
	},
}

// --- tool contract tests ---

func TestNewTools_Name(t *testing.T) {
	for _, tf := range newTools {
		t.Run(tf.name, func(t *testing.T) {
			tool := tf.newTool(executor.NewMock())
			if got := tool.Name(); got != tf.name {
				t.Errorf("Name() = %q, want %q", got, tf.name)
			}
		})
	}
}

func TestNewTools_Description(t *testing.T) {
	for _, tf := range newTools {
		t.Run(tf.name, func(t *testing.T) {
			tool := tf.newTool(executor.NewMock())
			if desc := tool.Description(); desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestNewTools_InputSchema(t *testing.T) {
	for _, tf := range newTools {
		t.Run(tf.name, func(t *testing.T) {
			tool := tf.newTool(executor.NewMock())

			var schema map[string]any
			if err := json.Unmarshal(tool.InputSchema(), &schema); err != nil {
				t.Fatalf("InputSchema() is not valid JSON: %v", err)
			}
			if schema["type"] != "object" {
				t.Errorf("schema type = %v, want \"object\"", schema["type"])
			}
			if _, ok := schema["properties"]; !ok {
				t.Error("schema missing \"properties\" key")
			}
		})
	}
}

func TestNewTools_MockOutput(t *testing.T) {
	const mockOutput = "mock-command-output-67890"

	for _, tf := range newTools {
		t.Run(tf.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(mockOutput)
			}
			tool := tf.newTool(mock)

			result, err := tool.Execute(context.Background(), mustJSON(tf.params(t)))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true, content: %s", result.Content[0].Text)
			}
			if len(result.Content) == 0 {
				t.Fatal("Execute() returned empty content")
			}
			if !strings.Contains(result.Content[0].Text, mockOutput) {
				t.Errorf("result content does not contain mock stdout %q, got: %s", mockOutput, result.Content[0].Text)
			}
		})
	}
}

// --- barzakh_inject ---

func TestInject_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewInject(mock)

	params := mustJSON(map[string]any{
		"input":   writeTempFile(t, "fw.bin"),
		"output":  "/tmp/implanted.bin",
		"payload": "trampoline",
		"arch":    "armv7",
		"size":    "131072",
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-adversary" {
		t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
	}
	want := []string{
		"inject-single", "--input", call.Args[2], "--output", "/tmp/implanted.bin",
		"--payload", "trampoline",
		"--arch", "armv7", "--size", "131072",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
	if !strings.HasPrefix(call.Args[2], "/") {
		t.Errorf("input should be the temp firmware path, got %q", call.Args[2])
	}
}

func TestInject_PayloadIsNameNotPath(t *testing.T) {
	// adversary_main.rs: inject-single --payload takes a payload NAME from
	// the catalog (like generate), not a file path.
	mock := executor.NewMock()
	tool := NewInject(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"input":   writeTempFile(t, "fw.bin"),
		"output":  "/tmp/out.bin",
		"payload": "/tmp/payload.bin",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("payload must be validated as a payload name, so a path should be rejected")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid payload name")
	}
}

func TestInject_MissingInputFile(t *testing.T) {
	mock := executor.NewMock()
	tool := NewInject(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"input":   "/nonexistent/fw.bin",
		"output":  "/tmp/out.bin",
		"payload": "trampoline",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for missing input firmware file")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for missing input file")
	}
}

func TestInject_ShellInjection(t *testing.T) {
	mock := executor.NewMock()
	tool := NewInject(mock)

	for field, value := range map[string]string{
		"input":  "/fw/rom.bin; rm -rf /",
		"output": "/tmp/out.bin | sh",
	} {
		params := map[string]any{
			"input":   writeTempFile(t, "fw.bin"),
			"output":  "/tmp/out.bin",
			"payload": "trampoline",
		}
		params[field] = value
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for shell metacharacter in %s", field)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

func TestInject_InvalidArchAndSize(t *testing.T) {
	mock := executor.NewMock()
	tool := NewInject(mock)

	for field, value := range map[string]string{"arch": "mips64", "size": "-1"} {
		params := map[string]any{
			"input":   writeTempFile(t, "fw.bin"),
			"output":  "/tmp/out.bin",
			"payload": "trampoline",
		}
		params[field] = value
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for invalid %s %q", field, value)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_esp_build ---

func TestEspBuild_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewEspBuild(mock)

	payload := writeTempFile(t, "payload.bin")
	params := mustJSON(map[string]any{
		"payload":  payload,
		"output":   "/tmp/esp.img",
		"size":     "32",
		"bootable": true,
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-adversary" {
		t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
	}
	want := []string{"esp", "build", "--payload", payload, "--output", "/tmp/esp.img", "--size", "32", "--bootable"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestEspBuild_BootableDefaultsToFalse(t *testing.T) {
	// adversary_main.rs: --bootable has default_value = "false" (the
	// synthetic scan image); the flag must only be passed when requested.
	mock := executor.NewMock()
	tool := NewEspBuild(mock)

	params := mustJSON(map[string]any{
		"payload": writeTempFile(t, "payload.bin"),
		"output":  "/tmp/esp.img",
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	for _, a := range call.Args {
		if a == "--bootable" {
			t.Error("args must not contain --bootable unless bootable=true (CLI default is false)")
		}
	}
}

func TestEspBuild_MissingPayloadFile(t *testing.T) {
	mock := executor.NewMock()
	tool := NewEspBuild(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"payload": "/nonexistent/payload.bin",
		"output":  "/tmp/esp.img",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for missing payload file")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for missing payload file")
	}
}

// --- barzakh_qemu ---

func TestQemu_Args(t *testing.T) {
	tests := []struct {
		name   string
		params func(t *testing.T) map[string]any
		want   []string
	}{
		{
			name: "run minimal",
			params: func(t *testing.T) map[string]any {
				return map[string]any{"action": "run", "esp": writeTempFile(t, "esp.img")}
			},
			want: []string{"qemu", "run", "--esp", "<esp>"},
		},
		{
			name: "run full",
			params: func(t *testing.T) map[string]any {
				return map[string]any{
					"action":   "run",
					"esp":      writeTempFile(t, "esp.img"),
					"arch":     "aarch64",
					"firmware": "/usr/share/OVMF.fd",
					"memory":   "512",
					"timeout":  "60",
				}
			},
			want: []string{"qemu", "run", "--esp", "<esp>", "--arch", "aarch64", "--firmware", "/usr/share/OVMF.fd", "--memory", "512", "--timeout", "60"},
		},
		{
			name: "dump",
			params: func(t *testing.T) map[string]any {
				return map[string]any{"action": "dump", "output": "/tmp/memdump.raw", "arch": "riscv64"}
			},
			want: []string{"qemu", "dump", "--output", "/tmp/memdump.raw", "--arch", "riscv64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewQemu(mock)

			params := tt.params(t)
			if _, err := tool.Execute(context.Background(), mustJSON(params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-adversary" {
				t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
			}
			want := append([]string{}, tt.want...)
			if want[2] == "--esp" {
				want[3] = params["esp"].(string)
			}
			if !reflect.DeepEqual(call.Args, want) {
				t.Errorf("args = %v, want %v", call.Args, want)
			}
		})
	}
}

func TestQemu_RunWithoutEsp(t *testing.T) {
	mock := executor.NewMock()
	tool := NewQemu(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "run"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for run without esp")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called when esp is missing")
	}
}

func TestQemu_DumpWithoutOutput(t *testing.T) {
	mock := executor.NewMock()
	tool := NewQemu(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "dump"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for dump without output")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called when output is missing")
	}
}

func TestQemu_RunMissingEspFile(t *testing.T) {
	mock := executor.NewMock()
	tool := NewQemu(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "run",
		"esp":    "/nonexistent/esp.img",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for missing esp image file")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for missing esp file")
	}
}

func TestQemu_InvalidActionAndArch(t *testing.T) {
	mock := executor.NewMock()
	tool := NewQemu(mock)

	for _, params := range []map[string]any{
		{"action": "boot"},
		{"action": "run", "esp": writeTempFile(t, "esp.img"), "arch": "mips64"},
		{"action": "run", "esp": writeTempFile(t, "esp.img"), "memory": "abc"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_range ---

func TestRange_Args(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "list",
			params: map[string]any{"action": "list"},
			want:   []string{"range", "list"},
		},
		{
			name:   "list with dir",
			params: map[string]any{"action": "list", "range_dir": "/opt/range"},
			want:   []string{"range", "list", "--range-dir", "/opt/range"},
		},
		{
			name:   "up minimal",
			params: map[string]any{"action": "up", "suite": "ring-2"},
			want:   []string{"range", "up", "--suite", "ring-2"},
		},
		{
			name: "up full",
			params: map[string]any{
				"action":           "up",
				"suite":            "/opt/range/ring-2.toml",
				"range_dir":        "/opt/range",
				"dry_run":          true,
				"keep":             true,
				"skip_memory_scan": true,
				"json":             true,
			},
			want: []string{
				"range", "up", "--suite", "/opt/range/ring-2.toml", "--range-dir", "/opt/range",
				"--dry-run", "--keep", "--skip-memory-scan", "--json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewRange(mock)

			if _, err := tool.Execute(context.Background(), mustJSON(tt.params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-scanner" {
				t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tt.want) {
				t.Errorf("args = %v, want %v", call.Args, tt.want)
			}
		})
	}
}

func TestRange_UpExitCode1_IsResult(t *testing.T) {
	// cmd_range exits 1 when report.pass == false (expected detections did
	// not fire) — a coverage result, not a failure.
	exec := &exitCodeExecutor{
		stdout:   `{"suite": "ring-2", "pass": false, "cases": [{"name": "blacklotus", "passed": false}]}`,
		exitCode: 1,
	}
	tool := NewRange(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "up",
		"suite":  "ring-2",
		"json":   true,
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("exit code 1 (suite assertions failed) must be a result, not an error; content: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "suite FAILED") {
		t.Errorf("result should note the failed suite, got: %s", result.Content[0].Text)
	}
}

func TestRange_UpExitCode0_Passed(t *testing.T) {
	exec := &exitCodeExecutor{
		stdout:   `{"suite": "ring-2", "pass": true}`,
		exitCode: 0,
	}
	tool := NewRange(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "up",
		"suite":  "ring-2",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("passing suite must not be an error; content: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "suite passed") {
		t.Errorf("result should note the suite passed, got: %s", result.Content[0].Text)
	}
}

func TestRange_UpExitCode2_IsError(t *testing.T) {
	exec := &exitCodeExecutor{
		stderr:   "range suite 'x' not found",
		exitCode: 2,
	}
	tool := NewRange(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "up",
		"suite":  "x",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("exit code 2 from range up must remain an error")
	}
}

func TestRange_TimeoutIsNotDetection(t *testing.T) {
	// A cancellation/timeout during a long-running range up must never be
	// misread as a failed-suite result.
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return []byte("{}") }
	mock.ErrFn = func(_ string, _ []string) error {
		return context.DeadlineExceeded
	}
	tool := NewRange(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "up",
		"suite":  "ring-2",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("timeout error must surface as an error, not a suite result")
	}
}

func TestRange_UpWithoutSuite(t *testing.T) {
	mock := executor.NewMock()
	tool := NewRange(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "up"}))
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for up without suite")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called when suite is missing")
	}
}

func TestRange_InvalidActionAndMetachars(t *testing.T) {
	mock := executor.NewMock()
	tool := NewRange(mock)

	for _, params := range []map[string]any{
		{"action": "down"},
		{"action": "up", "suite": "ring-2; rm -rf /"},
		{"action": "list", "range_dir": "/opt/range | sh"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_fuzz ---

func TestFuzz_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewFuzz(mock)

	params := mustJSON(map[string]any{
		"iterations": "100",
		"output_dir": "/tmp/fuzz-corpus",
		"mutate":     true,
		"json":       true,
		"protocol":   "dhcpv6",
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-scanner" {
		t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
	}
	want := []string{
		"fuzz", "--iterations", "100", "--output-dir", "/tmp/fuzz-corpus",
		"--mutate", "--json", "--protocol", "dhcpv6",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestFuzz_InvalidProtocolAndIterations(t *testing.T) {
	mock := executor.NewMock()
	tool := NewFuzz(mock)

	for _, params := range []map[string]any{
		{"protocol": "smb"},
		{"iterations": "abc"},
		{"iterations": "-5"},
		{"output_dir": "/tmp/fuzz; rm"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_history ---

func TestHistory_Args(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "list defaults",
			params: map[string]any{"action": "list"},
			want:   []string{"history", "list"},
		},
		{
			name:   "list with db and limit",
			params: map[string]any{"action": "list", "db": "/tmp/h.sqlite", "limit": "50"},
			want:   []string{"history", "list", "--db", "/tmp/h.sqlite", "--limit", "50"},
		},
		{
			name:   "show positional id",
			params: map[string]any{"action": "show", "id": "7", "db": "/tmp/h.sqlite"},
			want:   []string{"history", "show", "7", "--db", "/tmp/h.sqlite"},
		},
		{
			name:   "diff positional ids",
			params: map[string]any{"action": "diff", "a": "3", "b": "9", "db": "/tmp/h.sqlite"},
			want:   []string{"history", "diff", "3", "9", "--db", "/tmp/h.sqlite"},
		},
		{
			name:   "trends",
			params: map[string]any{"action": "trends", "db": "/tmp/h.sqlite"},
			want:   []string{"history", "trends", "--db", "/tmp/h.sqlite"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewHistory(mock)

			if _, err := tool.Execute(context.Background(), mustJSON(tt.params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-scanner" {
				t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tt.want) {
				t.Errorf("args = %v, want %v", call.Args, tt.want)
			}
		})
	}
}

func TestHistory_MissingRequired(t *testing.T) {
	mock := executor.NewMock()
	tool := NewHistory(mock)

	for _, params := range []map[string]any{
		{"action": "show"},
		{"action": "diff", "a": "3"},
		{"action": "diff", "b": "9"},
		{"action": "diff"},
		{"action": "purge"},
		{"action": "show", "id": "abc"},
		{"action": "show", "id": "1; rm"},
		{"action": "list", "limit": "-1"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_kb ---

func TestKb_Args(t *testing.T) {
	target := writeTempFile(t, "fw.bin")
	bundle := writeTempFile(t, "bundle.json")

	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "list",
			params: map[string]any{"action": "list", "db": "/tmp/kb.sqlite"},
			want:   []string{"kb", "list", "--db", "/tmp/kb.sqlite"},
		},
		{
			name:   "search",
			params: map[string]any{"action": "search", "query": "thinkpad", "db": "/tmp/kb.sqlite"},
			want:   []string{"kb", "search", "--query", "thinkpad", "--db", "/tmp/kb.sqlite"},
		},
		{
			name:   "export",
			params: map[string]any{"action": "export", "output": "/tmp/bundle.json", "anonymize": true, "db": "/tmp/kb.sqlite"},
			want:   []string{"kb", "export", "--output", "/tmp/bundle.json", "--anonymize", "--db", "/tmp/kb.sqlite"},
		},
		{
			name:   "import",
			params: map[string]any{"action": "import", "input": bundle, "db": "/tmp/kb.sqlite"},
			want:   []string{"kb", "import", "--input", bundle, "--db", "/tmp/kb.sqlite"},
		},
		{
			name: "add",
			params: map[string]any{
				"action":      "add",
				"target":      target,
				"vendor":      "lenovo",
				"device":      "thinkpad-x1",
				"family":      "tigerlake",
				"fw_version":  "3607",
				"arch":        "x86_64",
				"notes":       "reference image",
				"known_clean": true,
				"db":          "/tmp/kb.sqlite",
			},
			want: []string{
				"kb", "add", "--target", target,
				"--vendor", "lenovo", "--device", "thinkpad-x1", "--family", "tigerlake",
				"--fw-version", "3607", "--arch", "x86_64", "--notes", "reference image",
				"--known-clean", "--db", "/tmp/kb.sqlite",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewKb(mock)

			if _, err := tool.Execute(context.Background(), mustJSON(tt.params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-scanner" {
				t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tt.want) {
				t.Errorf("args = %v, want %v", call.Args, tt.want)
			}
		})
	}
}

func TestKb_MissingRequiredAndInvalid(t *testing.T) {
	mock := executor.NewMock()
	tool := NewKb(mock)

	for _, params := range []map[string]any{
		{"action": "add"},
		{"action": "add", "target": "/nonexistent/fw.bin"},
		{"action": "search"},
		{"action": "export"},
		{"action": "import"},
		{"action": "import", "input": "/nonexistent/bundle.json"},
		{"action": "delete"},
		{"action": "search", "query": "lenovo; rm -rf /"},
		{"action": "add", "target": writeTempFileWrapper(t, "fw.bin"), "notes": "bad `notes`"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// writeTempFileWrapper allows writeTempFile inside composite literals.
func writeTempFileWrapper(t *testing.T, name string) string {
	t.Helper()
	return writeTempFile(t, name)
}

// --- barzakh_ml ---

func TestMl_Args(t *testing.T) {
	tests := []struct {
		name   string
		params func(t *testing.T) map[string]any
		want   []string
	}{
		{
			name: "train",
			params: func(t *testing.T) map[string]any {
				return map[string]any{"action": "train", "corpus": t.TempDir(), "output": "/tmp/model.json"}
			},
			want: []string{"ml", "train", "--corpus", "<corpus>", "--output", "/tmp/model.json"},
		},
		{
			name: "evaluate",
			params: func(t *testing.T) map[string]any {
				return map[string]any{"action": "evaluate", "corpus": t.TempDir(), "model": writeTempFile(t, "model.json")}
			},
			want: []string{"ml", "evaluate", "--corpus", "<corpus>", "--model", "<model>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewMl(mock)

			params := tt.params(t)
			if _, err := tool.Execute(context.Background(), mustJSON(params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-scanner" {
				t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
			}
			want := append([]string{}, tt.want...)
			want[3] = params["corpus"].(string)
			if tt.name == "evaluate" {
				want[5] = params["model"].(string)
			}
			if !reflect.DeepEqual(call.Args, want) {
				t.Errorf("args = %v, want %v", call.Args, want)
			}
		})
	}
}

func TestMl_MissingRequiredAndInvalid(t *testing.T) {
	mock := executor.NewMock()
	tool := NewMl(mock)

	for _, params := range []map[string]any{
		{"action": "train"},
		{"action": "train", "corpus": "/nonexistent/corpus"},
		{"action": "evaluate", "corpus": t.TempDir()},
		{"action": "evaluate", "corpus": t.TempDir(), "model": "/nonexistent/model.json"},
		{"action": "predict", "corpus": t.TempDir()},
		{"action": "train", "corpus": "/tmp/corpus; rm"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- barzakh_manifest_validate ---

func TestManifestValidate_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewManifestValidate(mock)

	corpus := t.TempDir()
	manifest := writeTempFile(t, "corpus.toml")
	params := mustJSON(map[string]any{
		"corpus":   corpus,
		"manifest": manifest,
		"strict":   true,
		"split":    "test",
		"baseline": "/tmp/baseline.json",
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-scanner" {
		t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
	}
	want := []string{
		"validate", "--corpus", corpus, "--manifest", manifest,
		"--strict", "--split", "test", "--baseline", "/tmp/baseline.json",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestManifestValidate_MissingRequiredAndInvalid(t *testing.T) {
	mock := executor.NewMock()
	tool := NewManifestValidate(mock)

	for _, params := range []map[string]any{
		{},
		{"corpus": t.TempDir()},
		{"manifest": writeTempFileWrapper(t, "corpus.toml")},
		{"corpus": "/nonexistent/corpus", "manifest": writeTempFileWrapper(t, "m.toml")},
		{"corpus": t.TempDir(), "manifest": "/nonexistent/m.toml"},
		{"corpus": t.TempDir(), "manifest": writeTempFileWrapper(t, "m.toml"), "split": "prod"},
	} {
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected IsError=true for params %v", params)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid input")
		}
	}
}

// --- cross-cutting: missing required fields ---

func TestNewTools_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		tool   func(executor.Executor) mcp.Tool
		params map[string]any
	}{
		{"barzakh_inject without input", func(e executor.Executor) mcp.Tool { return NewInject(e) }, map[string]any{"output": "/tmp/o.bin", "payload": "trampoline"}},
		{"barzakh_inject without output", func(e executor.Executor) mcp.Tool { return NewInject(e) }, map[string]any{"input": "/fw/rom.bin", "payload": "trampoline"}},
		{"barzakh_inject without payload", func(e executor.Executor) mcp.Tool { return NewInject(e) }, map[string]any{"input": "/fw/rom.bin", "output": "/tmp/o.bin"}},
		{"barzakh_esp_build without payload", func(e executor.Executor) mcp.Tool { return NewEspBuild(e) }, map[string]any{"output": "/tmp/esp.img"}},
		{"barzakh_esp_build without output", func(e executor.Executor) mcp.Tool { return NewEspBuild(e) }, map[string]any{"payload": "/tmp/payload.bin"}},
		{"barzakh_qemu without action", func(e executor.Executor) mcp.Tool { return NewQemu(e) }, map[string]any{}},
		{"barzakh_range without action", func(e executor.Executor) mcp.Tool { return NewRange(e) }, map[string]any{}},
		{"barzakh_range up without suite", func(e executor.Executor) mcp.Tool { return NewRange(e) }, map[string]any{"action": "up"}},
		{"barzakh_history without action", func(e executor.Executor) mcp.Tool { return NewHistory(e) }, map[string]any{}},
		{"barzakh_history show without id", func(e executor.Executor) mcp.Tool { return NewHistory(e) }, map[string]any{"action": "show"}},
		{"barzakh_history diff without b", func(e executor.Executor) mcp.Tool { return NewHistory(e) }, map[string]any{"action": "diff", "a": "1"}},
		{"barzakh_kb without action", func(e executor.Executor) mcp.Tool { return NewKb(e) }, map[string]any{}},
		{"barzakh_kb add without target", func(e executor.Executor) mcp.Tool { return NewKb(e) }, map[string]any{"action": "add"}},
		{"barzakh_kb search without query", func(e executor.Executor) mcp.Tool { return NewKb(e) }, map[string]any{"action": "search"}},
		{"barzakh_kb export without output", func(e executor.Executor) mcp.Tool { return NewKb(e) }, map[string]any{"action": "export"}},
		{"barzakh_kb import without input", func(e executor.Executor) mcp.Tool { return NewKb(e) }, map[string]any{"action": "import"}},
		{"barzakh_ml without action", func(e executor.Executor) mcp.Tool { return NewMl(e) }, map[string]any{"corpus": "/tmp/corpus"}},
		{"barzakh_ml without corpus", func(e executor.Executor) mcp.Tool { return NewMl(e) }, map[string]any{"action": "train"}},
		{"barzakh_ml evaluate without model", func(e executor.Executor) mcp.Tool { return NewMl(e) }, map[string]any{"action": "evaluate", "corpus": "/tmp/corpus"}},
		{"barzakh_manifest_validate without corpus", func(e executor.Executor) mcp.Tool { return NewManifestValidate(e) }, map[string]any{"manifest": "/tmp/m.toml"}},
		{"barzakh_manifest_validate without manifest", func(e executor.Executor) mcp.Tool { return NewManifestValidate(e) }, map[string]any{"corpus": "/tmp/corpus"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := tt.tool(mock)

			result, err := tool.Execute(context.Background(), mustJSON(tt.params))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected IsError=true for missing required field")
			}
			if len(mock.Calls) > 0 {
				t.Error("executor should not be called when required fields are missing")
			}
		})
	}
}
