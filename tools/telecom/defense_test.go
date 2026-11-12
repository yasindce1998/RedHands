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

// newTestManager builds a BackgroundManager whose "staticzero-defense"
// allowlist entry points at a fake daemon script that sleeps until killed.
func newTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-staticzero-defense")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"staticzero-defense": bin},
	})
}

func bgTools(mgr *executor.BackgroundManager) []mcp.Tool {
	return []mcp.Tool{
		NewDefenseStart(mgr),
		NewDefenseStop(mgr),
		NewDefenseStatus(mgr),
	}
}

// firstProcess returns the managed process with the latest start time. The
// manager keeps stopped processes in its list, so tests that start more than
// one daemon use this to get the newest.
func firstProcess(t *testing.T, mgr *executor.BackgroundManager) executor.BackgroundStatus {
	t.Helper()
	statuses := mgr.List()
	if len(statuses) == 0 {
		t.Fatal("expected at least 1 managed process, got 0")
	}
	latest := statuses[0]
	for _, st := range statuses[1:] {
		if st.StartedAt.After(latest.StartedAt) {
			latest = st
		}
	}
	return latest
}

// ---------------------------------------------------------------------------
// Test: daemon lifecycle tool names, descriptions, schemas
// ---------------------------------------------------------------------------

func TestDefenseLifecycleTools_NameDescriptionSchema(t *testing.T) {
	mgr := newTestManager(t)
	tools := bgTools(mgr)

	wantNames := map[string]bool{
		"telecom_defense_start":  false,
		"telecom_defense_stop":   false,
		"telecom_defense_status": false,
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
		if !strings.Contains(desc, "authorized lab use only") {
			t.Errorf("tool %q description must mention authorized lab use only", name)
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

	startDesc := NewDefenseStart(mgr).Description()
	if !strings.Contains(startDesc, "root") || !strings.Contains(startDesc, "5.15") {
		t.Error("telecom_defense_start description must mention root and kernel >= 5.15 requirements")
	}
}

// ---------------------------------------------------------------------------
// Test: successful start, output files, stop, status
// ---------------------------------------------------------------------------

func TestDefenseStart_SuccessLifecycle(t *testing.T) {
	mgr := newTestManager(t)
	start := NewDefenseStart(mgr)
	stop := NewDefenseStop(mgr)
	status := NewDefenseStatus(mgr)

	dir := t.TempDir()
	logsDir := filepath.Join(dir, "nested", "logs") // must be created 0700
	config := filepath.Join(dir, "staticzero.toml")
	if err := os.WriteFile(config, []byte("[staticzero]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"modules":            "16,17,24",
		"group":              "telecom-advanced",
		"config":             config,
		"correlation_window": 30,
		"logs_dir":           logsDir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"Process ID:** proc_", "PID:**", "telecom_defense_stop", "telecom_defense_status", logsDir, "```json", `"process_id":"proc_`} {
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
	if st.Binary != "staticzero-defense" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{"--telecom-advanced", "--json", "--modules 16,17,24", "--config " + config, "--correlation-window 30"} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}

	// Output files follow the staticzero-defense-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".jsonl") || !strings.Contains(st.StdoutPath, "staticzero-defense-") {
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

func TestDefenseStart_DefaultsAndGroups(t *testing.T) {
	mgr := newTestManager(t)
	tool := NewDefenseStart(mgr)

	// Default group is telecom-detect; --json is always present.
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"logs_dir": t.TempDir()}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--telecom-detect") || !strings.Contains(args, "--json") {
		t.Errorf("expected --telecom-detect --json defaults, got: %s", args)
	}
	if strings.Contains(args, "--modules") || strings.Contains(args, "--config") || strings.Contains(args, "--correlation-window") {
		t.Errorf("optional flags must be omitted when unset, got: %s", args)
	}
	if _, err := NewDefenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}

	// "all" maps to --all.
	result, err = tool.Execute(context.Background(), mustJSON(map[string]any{"group": "all", "logs_dir": t.TempDir()}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	st = firstProcess(t, mgr)
	args = strings.Join(st.Args, " ")
	if !strings.Contains(args, "--all") || !strings.Contains(args, "--json") {
		t.Errorf("expected --all --json for group=all, got: %s", args)
	}
	if _, err := NewDefenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

func TestDefenseStatus_ListsAllProcesses(t *testing.T) {
	mgr := newTestManager(t)
	status := NewDefenseStatus(mgr)

	// Empty list is fine.
	result, err := status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No managed background processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// With a process, the list output names the binary (it may not be ours).
	result, _ = NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"logs_dir": t.TempDir()}))
	if result.IsError {
		t.Fatalf("unexpected start error: %s", result.Content[0].Text)
	}
	result, err = status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "staticzero-defense") || !strings.Contains(text, "proc_") {
		t.Errorf("expected binary and process ID in list output, got:\n%s", text)
	}
}

func TestDefenseStop_UnknownProcessID(t *testing.T) {
	mgr := newTestManager(t)
	result, err := NewDefenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_does_not_exist"}))
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

func TestDefenseStatus_UnknownProcessID(t *testing.T) {
	mgr := newTestManager(t)
	result, err := NewDefenseStatus(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_missing"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Test: telecom_defense_start rejects invalid input
// ---------------------------------------------------------------------------

func TestDefenseStart_RejectsInvalidInput(t *testing.T) {
	mgr := newTestManager(t)
	tool := NewDefenseStart(mgr)
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
		{"invalid group", `{"logs_dir":"` + dir + `","group":"telecom-quantum"}`, "invalid group"},
		{"config does not exist", `{"logs_dir":"` + dir + `","config":"/nonzero/config.toml"}`, "not accessible"},
		{"correlation window negative", `{"logs_dir":"` + dir + `","correlation_window":-5}`, "correlation_window"},
		{"correlation window zero", `{"logs_dir":"` + dir + `","correlation_window":0}`, "correlation_window"},
		{"correlation window too large", `{"logs_dir":"` + dir + `","correlation_window":100000}`, "correlation_window"},
		{"modules metachar", `{"logs_dir":"` + dir + `","modules":"16;rm -rf /"}`, "forbidden character"},
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

// The binary must be allowlisted; a manager that does not know
// staticzero-defense refuses to start it.
func TestDefenseStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
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

// Every shell metacharacter in the output directory is rejected before the
// daemon is launched.
func TestDefenseStart_LogsDirMetacharInjection(t *testing.T) {
	mgr := newTestManager(t)
	tool := NewDefenseStart(mgr)
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
