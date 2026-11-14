package firmware

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// allTools returns every tool in the firmware package instantiated with the
// given executor. This is the single source of truth for enumerating tools.
func allTools(exec executor.Executor) []mcp.Tool {
	return []mcp.Tool{
		NewFirmwareScan(exec),
		NewFirmwareExtract(exec),
		NewFirmwareEntropy(exec),
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// tempImageFile writes a small fake firmware image and returns its path.
func tempImageFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("\x1f\x8b\x08 fake firmware image with gzip magic"), 0o600); err != nil {
		t.Fatalf("create temp firmware file: %v", err)
	}
	return path
}

// writeLogFromArgs simulates binwalk's `-f <log> --csv` behavior for the
// MockExecutor: the CSV fixture is written to the path following -f in args.
// It returns stdout for the mocked run.
func writeLogFromArgs(t *testing.T, csvFixture string, stdout string) func(string, []string) []byte {
	t.Helper()
	return func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "-f" && i+1 < len(args) {
				if err := os.WriteFile(args[i+1], []byte(csvFixture), 0o600); err != nil {
					t.Errorf("mock failed to write CSV log: %v", err)
				}
			}
		}
		return []byte(stdout)
	}
}

func assertArgs(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return
		}
	}
	t.Errorf("expected args to contain %q %q, got %v", flag, value, args)
}

func assertFlag(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, a := range args {
		if a == flag {
			return
		}
	}
	t.Errorf("expected args to contain %q, got %v", flag, args)
}

func assertNoFlag(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, a := range args {
		if a == flag {
			t.Errorf("expected args NOT to contain %q, got %v", flag, args)
		}
	}
}

// assertLastArg asserts the positional target file is the final argument.
func assertLastArg(t *testing.T, args []string, value string) {
	t.Helper()
	if len(args) == 0 || args[len(args)-1] != value {
		t.Errorf("expected last arg to be %q, got %v", value, args)
	}
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string { return e.msg }

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

// ---------------------------------------------------------------------------
// Test: All tools have non-empty Name() and Description() that mention
// binwalk and the authorized-analysis restriction.
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
		if !strings.HasPrefix(name, "firmware_") {
			t.Errorf("tool %q: Name() missing firmware_ prefix", name)
		}
		if seen[name] {
			t.Errorf("duplicate tool name %q", name)
		}
		seen[name] = true
		if desc == "" {
			t.Errorf("tool %q has empty Description()", name)
			continue
		}
		if !strings.Contains(desc, "binwalk") {
			t.Errorf("tool %q: Description() must mention binwalk", name)
		}
		if !strings.Contains(desc, "authorized") {
			t.Errorf("tool %q: Description() must mention authorized use", name)
		}
	}
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
// Test: metacharacter injection is rejected for every user-supplied string
// parameter of every tool (the executor would reject these too; the wrapper
// must fail fast with a clear error before the run).
// ---------------------------------------------------------------------------

func TestAllTools_MetacharInjection(t *testing.T) {
	image := tempImageFile(t, "fw.bin")
	outDir := t.TempDir()

	fields := []struct {
		name   string
		params func(inj string) map[string]any
	}{
		{"scan image", func(inj string) map[string]any {
			return map[string]any{"image": "/tmp/fw.bin" + inj + "x"}
		}},
		{"scan include", func(inj string) map[string]any {
			return map[string]any{"image": image, "include": "squashfs" + inj + "x"}
		}},
		{"scan exclude", func(inj string) map[string]any {
			return map[string]any{"image": image, "exclude": "certificate" + inj + "x"}
		}},
		{"extract image", func(inj string) map[string]any {
			return map[string]any{"image": "/tmp/fw.bin" + inj + "x", "output_dir": outDir}
		}},
		{"extract output_dir", func(inj string) map[string]any {
			return map[string]any{"image": image, "output_dir": "/tmp/out" + inj + "x"}
		}},
		{"extract include", func(inj string) map[string]any {
			return map[string]any{"image": image, "output_dir": outDir, "include": "squashfs" + inj + "x"}
		}},
		{"extract exclude", func(inj string) map[string]any {
			return map[string]any{"image": image, "output_dir": outDir, "exclude": "gzip" + inj + "x"}
		}},
		{"extract dd", func(inj string) map[string]any {
			return map[string]any{"image": image, "output_dir": outDir, "dd": "squashfs:" + inj + "x"}
		}},
		{"entropy image", func(inj string) map[string]any {
			return map[string]any{"image": "/tmp/fw.bin" + inj + "x"}
		}},
	}

	tools := map[string]mcp.Tool{
		"scan":    NewFirmwareScan(executor.NewMock()),
		"extract": NewFirmwareExtract(executor.NewMock()),
		"entropy": NewFirmwareEntropy(executor.NewMock()),
	}

	for _, field := range fields {
		tool := tools[strings.SplitN(field.name, " ", 2)[0]]
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
