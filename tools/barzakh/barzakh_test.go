package barzakh

import (
	"context"
	"encoding/json"
	"fmt"
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

type toolFactory struct {
	name    string
	newTool func(executor.Executor) mcp.Tool
	params  map[string]any
}

var allTools = []toolFactory{
	{
		name:    "barzakh_list",
		newTool: func(e executor.Executor) mcp.Tool { return NewList(e) },
		params:  map[string]any{},
	},
	{
		name:    "barzakh_generate",
		newTool: func(e executor.Executor) mcp.Tool { return NewGenerate(e) },
		params:  map[string]any{"payload": "trampoline", "output": "/tmp/payload.bin"},
	},
	{
		name:    "barzakh_corpus",
		newTool: func(e executor.Executor) mcp.Tool { return NewCorpus(e) },
		params:  map[string]any{},
	},
	{
		name:    "barzakh_scan",
		newTool: func(e executor.Executor) mcp.Tool { return NewScan(e) },
		params:  map[string]any{"target": "/fw/rom.bin"},
	},
	{
		name:    "barzakh_validate",
		newTool: func(e executor.Executor) mcp.Tool { return NewValidate(e) },
		params:  map[string]any{"corpus": "/tmp/corpus"},
	},
	{
		name:    "barzakh_scenario",
		newTool: func(e executor.Executor) mcp.Tool { return NewScenario(e) },
		params:  map[string]any{"action": "list"},
	},
	{
		name:    "barzakh_robustness",
		newTool: func(e executor.Executor) mcp.Tool { return NewRobustness(e) },
		params:  map[string]any{},
	},
	{
		name:    "barzakh_detectors",
		newTool: func(e executor.Executor) mcp.Tool { return NewDetectors(e) },
		params:  map[string]any{"action": "list"},
	},
	{
		name:    "barzakh_baseline",
		newTool: func(e executor.Executor) mcp.Tool { return NewBaseline(e) },
		params:  map[string]any{"action": "show"},
	},
	{
		name:    "barzakh_intel",
		newTool: func(e executor.Executor) mcp.Tool { return NewIntel(e) },
		params:  map[string]any{"action": "feeds"},
	},
}

// --- table-driven tool contract tests ---

func TestName(t *testing.T) {
	for _, tf := range allTools {
		t.Run(tf.name, func(t *testing.T) {
			tool := tf.newTool(executor.NewMock())
			if got := tool.Name(); got != tf.name {
				t.Errorf("Name() = %q, want %q", got, tf.name)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	for _, tf := range allTools {
		t.Run(tf.name, func(t *testing.T) {
			tool := tf.newTool(executor.NewMock())
			if desc := tool.Description(); desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestInputSchema(t *testing.T) {
	for _, tf := range allTools {
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

func TestExecute_MockOutput(t *testing.T) {
	const mockOutput = "mock-command-output-12345"

	for _, tf := range allTools {
		t.Run(tf.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte(mockOutput)
			}
			tool := tf.newTool(mock)

			result, err := tool.Execute(context.Background(), mustJSON(tf.params))
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

// --- barzakh_scan ---

func TestScan_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScan(mock)

	params := mustJSON(map[string]any{
		"target":     "/fw/rom.bin",
		"baseline":   "/fw/known-good.json",
		"report":     "/tmp/report.sarif",
		"format":     "sarif",
		"scan_types": "spi,smm",
	})

	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-scanner" {
		t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
	}
	want := []string{
		"scan", "--target", "/fw/rom.bin", "--json",
		"--baseline", "/fw/known-good.json",
		"--report", "/tmp/report.sarif",
		"--format", "sarif",
		"--scan-types", "spi,smm",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
	for _, a := range call.Args {
		if a == "--output" {
			t.Error("args must not contain the nonexistent --output flag")
		}
	}
}

func TestScan_MinimalArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScan(mock)

	params := mustJSON(map[string]any{"target": "/fw/rom.bin"})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	want := []string{"scan", "--target", "/fw/rom.bin", "--json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestScan_ExitCode1_IsDetection(t *testing.T) {
	exec := &exitCodeExecutor{
		stdout:   `{"findings": [{"severity": "critical"}, {"severity": "high"}, {"severity": "critical"}]}`,
		exitCode: 1,
	}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("exit code 1 (bootkit detected) must be a result, not an error; content: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	for _, want := range []string{"BOOTKIT DETECTED", "**Findings:** 3", "critical: 2", "high: 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("detection result missing %q, got: %s", want, text)
		}
	}
}

func TestScan_ExitCode0_Clean(t *testing.T) {
	exec := &exitCodeExecutor{
		stdout:   `{"findings": []}`,
		exitCode: 0,
	}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("clean scan must not be an error; content: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "no bootkit indicators detected") {
		t.Errorf("clean scan result should state no indicators, got: %s", result.Content[0].Text)
	}
}

func TestScan_ExitCode2_IsError(t *testing.T) {
	exec := &exitCodeExecutor{
		stderr:   "scan incomplete: image truncated",
		exitCode: 2,
	}
	tool := NewScan(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("exit code 2 (scan incomplete) must remain an error")
	}
	if !strings.Contains(result.Content[0].Text, "scan incomplete") {
		t.Errorf("error should mention scan incomplete semantics, got: %s", result.Content[0].Text)
	}
}

func TestScan_TimeoutIsNotDetection(t *testing.T) {
	// A cancellation/timeout error must never be misread as a detection,
	// even if the killed process happens to report exit code 1.
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return []byte("{}") }
	mock.ErrFn = func(_ string, _ []string) error {
		return fmt.Errorf("execution cancelled or timed out: context deadline exceeded")
	}
	tool := NewScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"target": "/fw/rom.bin"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("timeout error must surface as an error, not a detection")
	}
}

func TestScan_InvalidFormat(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScan(mock)

	for _, format := range []string{"pdf", "xml", "OUTPUT"} {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"target": "/fw/rom.bin",
			"format": format,
		}))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("format %q should be rejected", format)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid format")
		}
	}
}

func TestScan_ValidFormats(t *testing.T) {
	for _, format := range []string{"json", "html", "markdown", "sarif", "csv", "ecs", "cef", "leef"} {
		t.Run(format, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewScan(mock)

			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
				"target": "/fw/rom.bin",
				"report": "/tmp/report.out",
				"format": format,
			}))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("format %q should be accepted, got: %s", format, result.Content[0].Text)
			}
			call := mock.LastCall()
			for i, a := range call.Args {
				if a == "--format" && i+1 < len(call.Args) && call.Args[i+1] == format {
					return
				}
			}
			t.Errorf("expected --format %q in args, got %v", format, call.Args)
		})
	}
}

func TestScan_ReportIsAPathNotBoolean(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScan(mock)

	// Regression: report used to be a boolean flag; barzakh-scanner's
	// --report takes a value, so a boolean input must now be rejected.
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target": "/fw/rom.bin",
		"report": true,
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("boolean report should be rejected (report is a file path now)")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid report type")
	}
}

func TestScan_ShellInjection(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScan(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"target": "/fw/rom.bin; rm -rf /",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for shell metacharacter in target")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid input")
	}
}

// --- barzakh_generate ---

func TestGenerate_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewGenerate(mock)

	params := mustJSON(map[string]any{
		"payload": "trampoline",
		"output":  "/tmp/payload.bin",
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
		"generate", "--payload", "trampoline", "--output", "/tmp/payload.bin",
		"--arch", "armv7", "--size", "131072",
	}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestGenerate_NewArches(t *testing.T) {
	for _, arch := range []string{"x86-64", "aarch64", "riscv64", "power64", "armv7"} {
		t.Run(arch, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewGenerate(mock)

			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
				"payload": "trampoline",
				"output":  "/tmp/payload.bin",
				"arch":    arch,
			}))
			if err != nil {
				t.Fatalf("Execute() returned error: %v", err)
			}
			if result.IsError {
				t.Fatalf("arch %q should be accepted, got: %s", arch, result.Content[0].Text)
			}
		})
	}
}

func TestGenerate_InvalidArch(t *testing.T) {
	mock := executor.NewMock()
	tool := NewGenerate(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"payload": "trampoline",
		"output":  "/tmp/payload.bin",
		"arch":    "mips64",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for unsupported arch")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid arch")
	}
}

// --- barzakh_validate ---

func TestValidate_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewValidate(mock)

	params := mustJSON(map[string]any{
		"corpus": "/tmp/corpus",
		"json":   true,
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-adversary" {
		t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
	}
	want := []string{"validate", "--corpus", "/tmp/corpus", "--json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestValidate_ShellInjection(t *testing.T) {
	mock := executor.NewMock()
	tool := NewValidate(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"corpus": "/tmp/corpus | sh",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for shell metacharacter in corpus path")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid input")
	}
}

// --- barzakh_scenario ---

func TestScenario_Args(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "list",
			params: map[string]any{"action": "list"},
			want:   []string{"scenario", "list"},
		},
		{
			name:   "show",
			params: map[string]any{"action": "show", "name": "blacklotus-chain"},
			want:   []string{"scenario", "show", "--name", "blacklotus-chain"},
		},
		{
			name: "run",
			params: map[string]any{
				"action": "run",
				"name":   "smm-persistence-chain",
				"output": "/tmp/artifacts",
				"json":   true,
			},
			want: []string{"scenario", "run", "--name", "smm-persistence-chain", "--output", "/tmp/artifacts", "--json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewScenario(mock)

			if _, err := tool.Execute(context.Background(), mustJSON(tt.params)); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-adversary" {
				t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tt.want) {
				t.Errorf("args = %v, want %v", call.Args, tt.want)
			}
		})
	}
}

func TestScenario_RunExitCode1_IsResult(t *testing.T) {
	exec := &exitCodeExecutor{
		stdout:   `{"chain": "blacklotus-chain", "detected": false, "stages": [{"stage": 1, "detected": true}, {"stage": 2, "detected": false}]}`,
		exitCode: 1,
	}
	tool := NewScenario(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "run",
		"name":   "blacklotus-chain",
		"json":   true,
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("exit code 1 (chain not fully detected) must be a result, not an error; content: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "NOT fully detected") {
		t.Errorf("result should note the chain was not fully detected, got: %s", result.Content[0].Text)
	}
}

func TestScenario_RunExitCode0_FullyDetected(t *testing.T) {
	exec := &exitCodeExecutor{
		stdout:   `{"chain": "smm-persistence-chain", "detected": true}`,
		exitCode: 0,
	}
	tool := NewScenario(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "run",
		"name":   "smm-persistence-chain",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("fully detected chain must not be an error; content: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "chain fully detected") {
		t.Errorf("result should note the chain was fully detected, got: %s", result.Content[0].Text)
	}
}

func TestScenario_RunExitCode2_IsError(t *testing.T) {
	exec := &exitCodeExecutor{
		stderr:   "qemu unavailable",
		exitCode: 2,
	}
	tool := NewScenario(exec)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "run",
		"name":   "blacklotus-chain",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("exit code 2 from scenario run must remain an error")
	}
}

func TestScenario_InvalidAction(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScenario(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "delete"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for invalid action")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid action")
	}
}

func TestScenario_NameShellInjection(t *testing.T) {
	mock := executor.NewMock()
	tool := NewScenario(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "run",
		"name":   "blacklotus-chain; rm -rf /",
	}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for shell metacharacter in name")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid input")
	}
}

// --- barzakh_robustness ---

func TestRobustness_ExactArgs(t *testing.T) {
	mock := executor.NewMock()
	tool := NewRobustness(mock)

	params := mustJSON(map[string]any{
		"filter":    "blacklotus",
		"mutations": "25",
		"json":      true,
	})
	if _, err := tool.Execute(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	call := mock.LastCall()
	if call.Binary != "barzakh-adversary" {
		t.Errorf("binary = %q, want barzakh-adversary", call.Binary)
	}
	want := []string{"robustness", "--filter", "blacklotus", "--mutations", "25", "--json"}
	if !reflect.DeepEqual(call.Args, want) {
		t.Errorf("args = %v, want %v", call.Args, want)
	}
}

func TestRobustness_InvalidMutations(t *testing.T) {
	mock := executor.NewMock()
	tool := NewRobustness(mock)

	for _, mutations := range []string{"abc", "-1", "10; rm", "1.5"} {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"mutations": mutations,
		}))
		if err != nil {
			t.Fatalf("Execute() returned error: %v", err)
		}
		if !result.IsError {
			t.Errorf("mutations %q should be rejected", mutations)
		}
		if len(mock.Calls) > 0 {
			t.Error("executor should not be called for invalid mutations")
		}
	}
}

// --- barzakh_detectors ---

func TestDetectors_Args(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "list",
			params: map[string]any{"action": "list"},
			want:   []string{"detectors", "list"},
		},
		{
			name:   "info",
			params: map[string]any{"action": "info", "name": "spi_flash_hook"},
			want:   []string{"detectors", "info", "--name", "spi_flash_hook"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewDetectors(mock)

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

func TestDetectors_InfoRequiresName(t *testing.T) {
	mock := executor.NewMock()
	tool := NewDetectors(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "info"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for info without name")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called when name is missing")
	}
}

// --- barzakh_baseline ---

func TestBaseline_Args(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "create",
			params: map[string]any{"action": "create", "target": "/fw/good.bin"},
			want:   []string{"baseline", "create", "--target", "/fw/good.bin"},
		},
		{
			name:   "show",
			params: map[string]any{"action": "show"},
			want:   []string{"baseline", "show"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewBaseline(mock)

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

func TestBaseline_CreateRequiresTarget(t *testing.T) {
	mock := executor.NewMock()
	tool := NewBaseline(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "create"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for create without target")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called when target is missing")
	}
}

// --- barzakh_intel ---

func TestIntel_Args(t *testing.T) {
	for _, action := range []string{"feeds", "misp", "attack", "stix"} {
		t.Run(action, func(t *testing.T) {
			mock := executor.NewMock()
			tool := NewIntel(mock)

			if _, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": action})); err != nil {
				t.Fatal(err)
			}

			call := mock.LastCall()
			if call.Binary != "barzakh-scanner" {
				t.Errorf("binary = %q, want barzakh-scanner", call.Binary)
			}
			want := []string{"intel", action}
			if !reflect.DeepEqual(call.Args, want) {
				t.Errorf("args = %v, want %v", call.Args, want)
			}
		})
	}
}

func TestIntel_InvalidAction(t *testing.T) {
	mock := executor.NewMock()
	tool := NewIntel(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"action": "osint"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for invalid intel action")
	}
	if len(mock.Calls) > 0 {
		t.Error("executor should not be called for invalid action")
	}
}

// --- cross-cutting: missing required fields ---

func TestMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		tool   func(executor.Executor) mcp.Tool
		params map[string]any
	}{
		{"barzakh_scan without target", func(e executor.Executor) mcp.Tool { return NewScan(e) }, map[string]any{}},
		{"barzakh_generate without payload", func(e executor.Executor) mcp.Tool { return NewGenerate(e) }, map[string]any{"output": "/tmp/x.bin"}},
		{"barzakh_generate without output", func(e executor.Executor) mcp.Tool { return NewGenerate(e) }, map[string]any{"payload": "trampoline"}},
		{"barzakh_validate without corpus", func(e executor.Executor) mcp.Tool { return NewValidate(e) }, map[string]any{}},
		{"barzakh_scenario without action", func(e executor.Executor) mcp.Tool { return NewScenario(e) }, map[string]any{}},
		{"barzakh_scenario show without name", func(e executor.Executor) mcp.Tool { return NewScenario(e) }, map[string]any{"action": "show"}},
		{"barzakh_scenario run without name", func(e executor.Executor) mcp.Tool { return NewScenario(e) }, map[string]any{"action": "run"}},
		{"barzakh_detectors without action", func(e executor.Executor) mcp.Tool { return NewDetectors(e) }, map[string]any{}},
		{"barzakh_detectors info without name", func(e executor.Executor) mcp.Tool { return NewDetectors(e) }, map[string]any{"action": "info"}},
		{"barzakh_baseline without action", func(e executor.Executor) mcp.Tool { return NewBaseline(e) }, map[string]any{}},
		{"barzakh_baseline create without target", func(e executor.Executor) mcp.Tool { return NewBaseline(e) }, map[string]any{"action": "create"}},
		{"barzakh_intel without action", func(e executor.Executor) mcp.Tool { return NewIntel(e) }, map[string]any{}},
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
