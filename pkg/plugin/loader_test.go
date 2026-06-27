package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// mockExecutor implements executor.Executor for testing.
type mockExecutor struct {
	lastBinary string
	lastArgs   []string
	result     *executor.Result
	err        error
}

func (m *mockExecutor) Run(ctx context.Context, binary string, args ...string) (*executor.Result, error) {
	m.lastBinary = binary
	m.lastArgs = args
	return m.result, m.err
}

func TestLoadPluginsNonExistentDirectory(t *testing.T) {
	exec := &mockExecutor{}
	tools := LoadPlugins("/nonexistent/path/that/does/not/exist", exec)
	if tools != nil {
		t.Errorf("expected nil for non-existent directory, got %v", tools)
	}
}

func TestLoadPluginsValidDefinition(t *testing.T) {
	// Create a temporary directory with a plugin definition
	dir := t.TempDir()

	def := Definition{
		Name:         "test_scanner",
		Description:  "A test scanner tool",
		Binary:       "nmap",
		ArgsTemplate: []string{"-sV", "{{.target}}"},
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}}}`),
	}

	data, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("failed to marshal definition: %v", err)
	}

	err = os.WriteFile(filepath.Join(dir, "scanner.json"), data, 0644)
	if err != nil {
		t.Fatalf("failed to write plugin file: %v", err)
	}

	exec := &mockExecutor{}
	tools := LoadPlugins(dir, exec)

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	if tools[0].Name() != "test_scanner" {
		t.Errorf("tool name = %q, want %q", tools[0].Name(), "test_scanner")
	}
}

func TestLoadPluginsSkipsInvalidFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a file with missing name field
	noName := `{"description":"no name","binary":"nmap"}`
	err := os.WriteFile(filepath.Join(dir, "no_name.json"), []byte(noName), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Write a file with missing binary field
	noBinary := `{"name":"test","description":"no binary"}`
	err = os.WriteFile(filepath.Join(dir, "no_binary.json"), []byte(noBinary), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Write an invalid JSON file
	err = os.WriteFile(filepath.Join(dir, "invalid.json"), []byte(`{not json}`), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Write a non-JSON file (should be ignored)
	err = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a plugin"), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	exec := &mockExecutor{}
	tools := LoadPlugins(dir, exec)

	if len(tools) != 0 {
		t.Errorf("expected 0 valid tools, got %d", len(tools))
	}
}

func TestPluginToolNameDescriptionSchema(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"}}}`)

	tool := &PluginTool{
		def: Definition{
			Name:        "port_scanner",
			Description: "Scans ports on a target host",
			Binary:      "masscan",
			InputSchema: schema,
		},
	}

	if tool.Name() != "port_scanner" {
		t.Errorf("Name() = %q, want %q", tool.Name(), "port_scanner")
	}
	if tool.Description() != "Scans ports on a target host" {
		t.Errorf("Description() = %q, want %q", tool.Description(), "Scans ports on a target host")
	}

	gotSchema := tool.InputSchema()
	if string(gotSchema) != string(schema) {
		t.Errorf("InputSchema() = %s, want %s", string(gotSchema), string(schema))
	}
}

func TestTemplateRendering(t *testing.T) {
	tests := []struct {
		name     string
		template string
		data     map[string]any
		expected string
	}{
		{
			name:     "no template markers",
			template: "-sV",
			data:     map[string]any{"target": "10.0.0.1"},
			expected: "-sV",
		},
		{
			name:     "simple variable",
			template: "{{.target}}",
			data:     map[string]any{"target": "10.0.0.1"},
			expected: "10.0.0.1",
		},
		{
			name:     "mixed static and template",
			template: "--host={{.host}}",
			data:     map[string]any{"host": "example.com"},
			expected: "--host=example.com",
		},
		{
			name:     "missing key returns zero value",
			template: "{{.missing}}",
			data:     map[string]any{"other": "value"},
			expected: "<no value>",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := renderTemplate(tc.template, tc.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("renderTemplate(%q) = %q, want %q", tc.template, result, tc.expected)
			}
		})
	}
}

func TestTemplateRenderingInvalidTemplate(t *testing.T) {
	_, err := renderTemplate("{{.unclosed", map[string]any{})
	if err == nil {
		t.Error("expected error for invalid template syntax")
	}
}

func TestPluginToolExecute(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("scan results here"),
			Stderr:   nil,
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "nmap_scan",
			Description:  "Run nmap",
			Binary:       "nmap",
			ArgsTemplate: []string{"-sV", "{{.target}}"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	params := json.RawMessage(`{"target":"192.168.1.1"}`)
	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Error("expected no error in result")
	}

	// Check the executor received correct args
	if exec.lastBinary != "nmap" {
		t.Errorf("binary = %q, want %q", exec.lastBinary, "nmap")
	}
	if len(exec.lastArgs) != 2 {
		t.Fatalf("expected 2 args, got %d: %v", len(exec.lastArgs), exec.lastArgs)
	}
	if exec.lastArgs[0] != "-sV" {
		t.Errorf("arg[0] = %q, want %q", exec.lastArgs[0], "-sV")
	}
	if exec.lastArgs[1] != "192.168.1.1" {
		t.Errorf("arg[1] = %q, want %q", exec.lastArgs[1], "192.168.1.1")
	}

	// Check output contains the stdout
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	text := result.Content[0].Text
	if text == "" {
		t.Error("expected non-empty result text")
	}
}

func TestPluginToolExecuteInvalidParams(t *testing.T) {
	exec := &mockExecutor{}
	tool := &PluginTool{
		def: Definition{
			Name:         "test",
			Binary:       "test",
			ArgsTemplate: []string{"{{.target}}"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	// Invalid JSON params
	result, err := tool.Execute(context.Background(), json.RawMessage(`{invalid`))
	if err != nil {
		t.Fatalf("Execute should not return go error for bad params, got: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for invalid params")
	}
}

func TestLoadPluginsMultipleValid(t *testing.T) {
	dir := t.TempDir()

	defs := []Definition{
		{Name: "tool_a", Description: "Tool A", Binary: "a_bin", InputSchema: json.RawMessage(`{}`)},
		{Name: "tool_b", Description: "Tool B", Binary: "b_bin", InputSchema: json.RawMessage(`{}`)},
	}

	for i, def := range defs {
		data, _ := json.Marshal(def)
		filename := filepath.Join(dir, string(rune('a'+i))+".json")
		if err := os.WriteFile(filename, data, 0644); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}

	exec := &mockExecutor{}
	tools := LoadPlugins(dir, exec)

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
}

func TestLoadPluginsEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	exec := &mockExecutor{}
	tools := LoadPlugins(dir, exec)

	if len(tools) != 0 {
		t.Errorf("expected 0 tools for empty directory, got %d", len(tools))
	}
}

func TestLoadPluginsSkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory (should be ignored by loader)
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	exec := &mockExecutor{}
	tools := LoadPlugins(dir, exec)

	if len(tools) != 0 {
		t.Errorf("expected 0 tools when only subdirectories exist, got %d", len(tools))
	}
}

func TestPluginToolExecuteBuildsArgsFromTemplate(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("output"),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "multi_arg",
			Binary:       "scanner",
			ArgsTemplate: []string{"--host", "{{.host}}", "--port", "{{.port}}", "--proto", "{{.proto}}"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	params := json.RawMessage(`{"host":"10.0.0.1","port":"443","proto":"tcp"}`)
	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}

	expectedArgs := []string{"--host", "10.0.0.1", "--port", "443", "--proto", "tcp"}
	if len(exec.lastArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(exec.lastArgs), exec.lastArgs)
	}
	for i, want := range expectedArgs {
		if exec.lastArgs[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, exec.lastArgs[i], want)
		}
	}
}

func TestPluginToolExecuteEmptyTemplateResultSkipped(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("done"),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "conditional",
			Binary:       "tool",
			ArgsTemplate: []string{"--target", "{{.target}}", "{{if .verbose}}--verbose{{end}}"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	// Without verbose - empty rendered template should be omitted
	params := json.RawMessage(`{"target":"host.local"}`)
	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedArgs := []string{"--target", "host.local"}
	if len(exec.lastArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args (empty skipped), got %d: %v", len(expectedArgs), len(exec.lastArgs), exec.lastArgs)
	}
	for i, want := range expectedArgs {
		if exec.lastArgs[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, exec.lastArgs[i], want)
		}
	}
}

func TestPluginToolExecuteWithConditionalFlagPresent(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("verbose output"),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "conditional",
			Binary:       "tool",
			ArgsTemplate: []string{"--target", "{{.target}}", "{{if .verbose}}--verbose{{end}}"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	// With verbose=true - the flag should be included
	params := json.RawMessage(`{"target":"host.local","verbose":true}`)
	_, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedArgs := []string{"--target", "host.local", "--verbose"}
	if len(exec.lastArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(exec.lastArgs), exec.lastArgs)
	}
	for i, want := range expectedArgs {
		if exec.lastArgs[i] != want {
			t.Errorf("arg[%d] = %q, want %q", i, exec.lastArgs[i], want)
		}
	}
}

func TestPluginToolExecuteExecutorError(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   nil,
			Stderr:   []byte("permission denied"),
			ExitCode: 1,
		},
		err: fmt.Errorf("binary not allowed: bad_bin"),
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "failing_tool",
			Binary:       "bad_bin",
			ArgsTemplate: []string{"arg1"},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Execute should not return Go error, got: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true when executor fails")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "binary not allowed") {
		t.Errorf("expected error message in content, got: %s", text)
	}
	if !strings.Contains(text, "permission denied") {
		t.Errorf("expected stderr in content, got: %s", text)
	}
}

func TestPluginToolExecuteOutputFormatting(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("line1\nline2\nline3"),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "formatter",
			Binary:       "cmd",
			ArgsTemplate: []string{},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "## formatter") {
		t.Errorf("expected heading '## formatter' in output, got:\n%s", text)
	}
	if !strings.Contains(text, "```\nline1\nline2\nline3\n```") {
		t.Errorf("expected stdout in code block, got:\n%s", text)
	}
}

func TestPluginToolExecuteEmptyOutput(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte(""),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "quiet_tool",
			Binary:       "quiet",
			ArgsTemplate: []string{},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "Command completed with no output") {
		t.Errorf("expected 'Command completed with no output', got:\n%s", text)
	}
}

func TestPluginToolExecuteStderrIncluded(t *testing.T) {
	exec := &mockExecutor{
		result: &executor.Result{
			Stdout:   []byte("main output"),
			Stderr:   []byte("warning: something"),
			ExitCode: 0,
		},
	}

	tool := &PluginTool{
		def: Definition{
			Name:         "warn_tool",
			Binary:       "cmd",
			ArgsTemplate: []string{},
			InputSchema:  json.RawMessage(`{}`),
		},
		exec: exec,
	}

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("unexpected error result")
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "main output") {
		t.Errorf("expected stdout in output, got:\n%s", text)
	}
	if !strings.Contains(text, "**Stderr**") {
		t.Errorf("expected stderr section in output, got:\n%s", text)
	}
	if !strings.Contains(text, "warning: something") {
		t.Errorf("expected stderr content in output, got:\n%s", text)
	}
}

func TestLoadPluginsDefaultDirectory(t *testing.T) {
	// When dir is empty string, LoadPlugins defaults to "./plugins"
	// which likely doesn't exist in the test env, so should return nil
	exec := &mockExecutor{}
	tools := LoadPlugins("", exec)

	// Should gracefully handle non-existent default directory
	if tools != nil {
		t.Logf("default plugins directory exists with %d tools (acceptable)", len(tools))
	}
}
