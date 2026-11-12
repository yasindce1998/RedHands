package telecom

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

// newCorrelatorTestManager builds a BackgroundManager whose
// "protocol-correlator" allowlist entry points at a fake daemon script that
// sleeps until killed.
func newCorrelatorTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-protocol-correlator")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{correlatorBinary: bin},
	})
}

// newCorrelatorDualTestManager allowlists both the correlator and offense
// fake daemons so binary-filtered status listing can be tested.
func newCorrelatorDualTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	allowed := map[string]string{}
	for _, name := range []string{correlatorBinary, offenseBinary} {
		bin := filepath.Join(dir, "fake-"+name)
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		allowed[name] = bin
	}
	return executor.NewBackgroundManager(executor.Config{AllowedBinaries: allowed})
}

func correlatorBgTools(mgr *executor.BackgroundManager) []mcp.Tool {
	return []mcp.Tool{
		NewCorrelatorStart(mgr),
		NewCorrelatorStop(mgr),
		NewCorrelatorStatus(mgr),
	}
}

// ---------------------------------------------------------------------------
// Test: correlator lifecycle tool names, descriptions, schemas
// ---------------------------------------------------------------------------

func TestCorrelatorLifecycleTools_NameDescriptionSchema(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	tools := correlatorBgTools(mgr)

	wantNames := map[string]bool{
		"telecom_correlator_start":  false,
		"telecom_correlator_stop":   false,
		"telecom_correlator_status": false,
	}
	for _, tool := range tools {
		name := tool.Name()
		if _, ok := wantNames[name]; !ok {
			t.Errorf("unexpected tool name %q", name)
			continue
		}
		wantNames[name] = true

		desc := tool.Description()
		if !strings.Contains(desc, "StaticZero") {
			t.Errorf("tool %q description must mention StaticZero", name)
		}
		if !strings.Contains(desc, "authorized") || !strings.Contains(desc, "lab") {
			t.Errorf("tool %q description must mention authorized lab use", name)
		}

		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema(), &schema); err != nil {
			t.Errorf("tool %q: InputSchema() is invalid JSON: %v", name, err)
			continue
		}
		if tp, ok := schema["type"]; !ok || tp != "object" {
			t.Errorf("tool %q: InputSchema() missing \"type\": \"object\"", name)
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("missing lifecycle tool %q", name)
		}
	}

	startDesc := NewCorrelatorStart(mgr).Description()
	for _, want := range []string{"7892", "JSON-lines", "IMSI", "correlation"} {
		if !strings.Contains(startDesc, want) {
			t.Errorf("telecom_correlator_start description must mention %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: successful start, output files, stop, status
// ---------------------------------------------------------------------------

func TestCorrelatorStart_SuccessLifecycle(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	start := NewCorrelatorStart(mgr)
	stop := NewCorrelatorStop(mgr)
	status := NewCorrelatorStatus(mgr)

	dir := t.TempDir()
	logsDir := filepath.Join(dir, "nested", "correlator") // must be created 0700

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"logs_dir":      logsDir,
		"ingest_port":   7920,
		"window_ms":     10000,
		"threshold":     0.85,
		"output_format": "csv",
		"max_events":    5000,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{
		"Protocol Correlator Started",
		"Process ID:** proc_",
		"PID:**",
		"```json",
		`"process_id":"proc_`,
		`"ingest_port":7920`,
		"127.0.0.1:7920",
		"telecom_correlator_stop",
		"telecom_correlator_status",
		logsDir,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}

	// The output directory was created with 0700.
	info, err := os.Stat(logsDir)
	if err != nil {
		t.Fatalf("logs_dir not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 directory, got %v", info.Mode().Perm())
	}

	// Exactly one managed process, running, with the expected args and files.
	st := firstProcess(t, mgr)
	if !st.Running || st.PID <= 0 {
		t.Fatalf("expected running process, got %+v", st)
	}
	if st.Binary != correlatorBinary {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{
		"--ingest-port 7920",
		"--window-ms 10000",
		"--threshold 0.85",
		"--output csv",
		"--max-events 5000",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}

	// Output files follow the protocol-correlator-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".log") || !strings.Contains(st.StdoutPath, "protocol-correlator-") {
		t.Errorf("unexpected stdout path %q", st.StdoutPath)
	}
	if !strings.HasSuffix(st.StderrPath, ".err") {
		t.Errorf("unexpected stderr path %q", st.StderrPath)
	}
	for _, path := range []string{st.StdoutPath, st.StderrPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected output file %s to exist: %v", path, err)
		}
	}

	// Status by process ID reports the running daemon.
	result, err = status.Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Running:** yes") {
		t.Errorf("expected running status, got:\n%s", result.Content[0].Text)
	}

	// Stop, then status shows not running.
	result, err = stop.Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected stop error: %s", result.Content[0].Text)
	}

	result, err = status.Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	text = result.Content[0].Text
	if !strings.Contains(text, "Running:** no") || !strings.Contains(text, "Exit code:**") {
		t.Errorf("expected stopped status with exit code, got:\n%s", text)
	}

	// Stopping an exited process is a no-op, not an error.
	result, _ = stop.Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID}))
	if result.IsError {
		t.Errorf("double stop should be a no-op, got: %s", result.Content[0].Text)
	}
}

func TestCorrelatorStart_Defaults(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	tool := NewCorrelatorStart(mgr)

	// With no optional flags the daemon runs on the binary's defaults; the
	// fenced JSON block still reports the resolved ingest port and format.
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"logs_dir": t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, `"ingest_port":7892`) {
		t.Errorf("expected default ingest port in JSON block, got:\n%s", text)
	}
	if !strings.Contains(text, "(json)") && !strings.Contains(text, "**Threat output (json):**") {
		t.Errorf("expected default json output format in output, got:\n%s", text)
	}

	st := firstProcess(t, mgr)
	if len(st.Args) != 0 {
		t.Errorf("expected no flags with all defaults, got: %v", st.Args)
	}
	if _, err := NewCorrelatorStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: telecom_correlator_start rejects invalid input
// ---------------------------------------------------------------------------

func TestCorrelatorStart_RejectsInvalidInput(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	tool := NewCorrelatorStart(mgr)
	dir := t.TempDir()
	fileWhereDirNeeded := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fileWhereDirNeeded, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing logs_dir", `{}`, "logs_dir is required"},
		{"ingest port too high", `{"logs_dir":"` + dir + `","ingest_port":70000}`, "ingest_port must be 1-65535"},
		{"ingest port negative", `{"logs_dir":"` + dir + `","ingest_port":-1}`, "ingest_port must be 1-65535"},
		{"window too large", `{"logs_dir":"` + dir + `","window_ms":4000000}`, "window_ms must be 1-3600000"},
		{"window negative", `{"logs_dir":"` + dir + `","window_ms":-100}`, "window_ms must be 1-3600000"},
		{"threshold above one", `{"logs_dir":"` + dir + `","threshold":1.5}`, "threshold must be between 0.0 and 1.0"},
		{"threshold negative", `{"logs_dir":"` + dir + `","threshold":-0.1}`, "threshold must be between 0.0 and 1.0"},
		{"bad output format", `{"logs_dir":"` + dir + `","output_format":"xml"}`, "invalid output_format"},
		{"max events too large", `{"logs_dir":"` + dir + `","max_events":2000000}`, "max_events must be 1-1000000"},
		{"max events negative", `{"logs_dir":"` + dir + `","max_events":-5}`, "max_events must be 1-1000000"},
		{"logs_dir metachar", `{"logs_dir":"/tmp/logs;evil"}`, "forbidden character"},
		{"logs_dir is a file", `{"logs_dir":"` + fileWhereDirNeeded + `"}`, "not a directory"},
		{"bad json", `{invalid`, "invalid input"},
		{"wrong type", `{"logs_dir":123}`, "invalid input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tool.Execute(context.Background(), json.RawMessage(tc.params))
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

// Every shell metacharacter in the output directory is rejected before the
// daemon is launched.
func TestCorrelatorStart_LogsDirMetacharInjection(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	tool := NewCorrelatorStart(mgr)
	for _, char := range shellMetachars {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"logs_dir": "/tmp/logs" + char + "evil",
		}))
		if err != nil {
			t.Fatalf("Execute returned Go error: %v", err)
		}
		if !result.IsError {
			t.Errorf("expected rejection for metachar %q, but got success", char)
			continue
		}
		if !strings.Contains(result.Content[0].Text, "forbidden character") {
			t.Errorf("expected forbidden-character error for %q, got: %s", char, result.Content[0].Text)
		}
	}
}

// The binary must be allowlisted; a manager that does not know
// protocol-correlator refuses to start it.
func TestCorrelatorStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewCorrelatorStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"logs_dir": t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected allowlist rejection")
	}
	if !strings.Contains(result.Content[0].Text, "binary not allowed") {
		t.Errorf("expected allowlist error, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: status listing is filtered to the correlator binary
// ---------------------------------------------------------------------------

func TestCorrelatorStatus_ListsOnlyCorrelatorProcesses(t *testing.T) {
	mgr := newCorrelatorDualTestManager(t)
	status := NewCorrelatorStatus(mgr)

	// Empty filtered list is fine.
	result, err := status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No managed protocol-correlator processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// Start one daemon of each binary; the correlator status list shows only
	// the correlator.
	result, _ = NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"groups":   []string{"telecom"},
		"logs_dir": t.TempDir(),
	}))
	if result.IsError {
		t.Fatalf("offense start failed: %s", result.Content[0].Text)
	}
	result, _ = NewCorrelatorStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"logs_dir": t.TempDir(),
	}))
	if result.IsError {
		t.Fatalf("correlator start failed: %s", result.Content[0].Text)
	}

	result, err = status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "protocol-correlator") || !strings.Contains(text, "proc_") {
		t.Errorf("expected correlator binary and process ID in list output, got:\n%s", text)
	}
	if strings.Contains(text, "staticzero-offense") {
		t.Errorf("correlator status list must not show offense processes, got:\n%s", text)
	}
	if strings.Count(text, "### proc_") != 1 {
		t.Errorf("expected exactly one listed process, got:\n%s", text)
	}
}

func TestCorrelatorStop_UnknownProcessID(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	result, err := NewCorrelatorStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_does_not_exist"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for unknown process ID")
	}
	if !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %s", result.Content[0].Text)
	}
}

func TestCorrelatorStatus_UnknownProcessID(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	result, err := NewCorrelatorStatus(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_missing"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %+v", result)
	}
}

func TestCorrelatorStop_MissingProcessID(t *testing.T) {
	mgr := newCorrelatorTestManager(t)
	result, err := NewCorrelatorStop(mgr).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "process_id is required") {
		t.Errorf("expected process_id-required error, got: %+v", result)
	}
}
