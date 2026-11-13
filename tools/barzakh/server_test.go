package barzakh

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

// newBZServerManager builds a BackgroundManager whose "barzakh-server"
// allowlist entry points at a fake daemon script that sleeps until killed.
func newBZServerManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-barzakh-server")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"barzakh-server": bin},
	})
}

// bzFirstProcess returns the managed process with the latest start time. The
// manager keeps stopped processes in its list, so tests that start more than
// one daemon use this to get the newest.
func bzFirstProcess(t *testing.T, mgr *executor.BackgroundManager) executor.BackgroundStatus {
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

func TestBZServerLifecycleTools_NameDescriptionSchema(t *testing.T) {
	mgr := newBZServerManager(t)
	tools := []mcp.Tool{NewServerStart(mgr), NewServerStop(mgr), NewServerStatus(mgr)}

	wantNames := map[string]bool{
		"barzakh_server_start":  false,
		"barzakh_server_stop":   false,
		"barzakh_server_status": false,
	}
	for _, tool := range tools {
		name := tool.Name()
		if _, ok := wantNames[name]; !ok {
			t.Errorf("unexpected tool name %q", name)
			continue
		}
		wantNames[name] = true

		desc := tool.Description()
		if !strings.Contains(desc, "Barzakh") {
			t.Errorf("tool %q description must mention Barzakh", name)
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

	startDesc := NewServerStart(mgr).Description()
	for _, want := range []string{"BARZAKH_API_KEY", "8420", "barzakh-server"} {
		if !strings.Contains(startDesc, want) {
			t.Errorf("barzakh_server_start description must mention %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: successful start, output files, stop, status
// ---------------------------------------------------------------------------

func TestBZServerStart_SuccessLifecycle(t *testing.T) {
	mgr := newBZServerManager(t)
	start := NewServerStart(mgr)
	stop := NewServerStop(mgr)
	status := NewServerStatus(mgr)

	dir := t.TempDir()
	dataDir := filepath.Join(dir, "nested", "state") // must be created 0700
	scanRoot := filepath.Join(dir, "firmware")
	if err := os.MkdirAll(scanRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanRoot, "rom.bin"), []byte("fw"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"data_dir":  dataDir,
		"bind":      "127.0.0.1",
		"port":      9999,
		"api_key":   "secret-key-1",
		"scan_root": scanRoot,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{
		"Process ID:** proc_", "PID:**", "barzakh_server_stop", "barzakh_server_status",
		dataDir, "```json", `"process_id":"proc_`, "http://127.0.0.1:9999",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}
	// The API key is redacted in the rendered command echo.
	if !strings.Contains(text, "--api-key <redacted>") || strings.Contains(text, "secret-key-1") {
		t.Errorf("expected redacted API key in start output, got:\n%s", text)
	}

	// The state directory was created with 0700.
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("data_dir not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 directory, got %v", info.Mode().Perm())
	}

	// Exactly one managed process, running, with the expected args and files.
	st := bzFirstProcess(t, mgr)
	if !st.Running || st.PID <= 0 {
		t.Fatalf("expected running process, got %+v", st)
	}
	if st.Binary != "barzakh-server" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{
		"--db", ".db", "--payloads-dir " + scanRoot, "--port 9999", "--api-key REDACTED",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	// The pinned barzakh-server release rejects --scan-root and --bind.
	for _, banned := range []string{"--scan-root", "--bind"} {
		if strings.Contains(args, banned) {
			t.Errorf("daemon args must not contain %q (unsupported by pinned binary), got: %s", banned, args)
		}
	}
	if !strings.HasPrefix(st.StdoutPath, dataDir) {
		t.Errorf("stdout path %q must live under data_dir %q", st.StdoutPath, dataDir)
	}

	// Output files follow the barzakh-server-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".log") || !strings.Contains(st.StdoutPath, "barzakh-server-") {
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

func TestBZServerStart_Defaults(t *testing.T) {
	mgr := newBZServerManager(t)
	tool := NewServerStart(mgr)

	dataDir := t.TempDir()
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"data_dir": dataDir}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	st := bzFirstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	for _, want := range []string{
		"--db", ".db", "--payloads-dir " + filepath.Join(dataDir, "payloads"),
		"--port 8420",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	if strings.Contains(args, "--api-key") {
		t.Errorf("optional --api-key must be omitted when unset, got: %s", args)
	}
	// The default payloads/scan-root directory was created for the daemon.
	if info, err := os.Stat(filepath.Join(dataDir, "payloads")); err != nil || !info.IsDir() {
		t.Errorf("expected payloads dir under data_dir, got err=%v", err)
	}
	if _, err := NewServerStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

func TestBZServerStatus_ListsFilteredProcesses(t *testing.T) {
	dir := t.TempDir()
	otherBin := filepath.Join(dir, "fake-other-daemon")
	if err := os.WriteFile(otherBin, []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	kdBin := filepath.Join(dir, "fake-barzakh-server")
	if err := os.WriteFile(kdBin, []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{
			"barzakh-server": kdBin,
			"other-daemon":   otherBin,
		},
	})
	status := NewServerStatus(mgr)

	// Another engine's daemon is managed but filtered out of the listing.
	if _, err := mgr.Start(context.Background(), "other-daemon", nil, filepath.Join(dir, "other.log"), filepath.Join(dir, "other.err")); err != nil {
		t.Fatal(err)
	}
	result, err := status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No managed barzakh-server processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// With a barzakh-server process, the list shows it but not the other daemon.
	result, _ = NewServerStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"data_dir": t.TempDir()}))
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
	if !strings.Contains(text, "barzakh-server") || !strings.Contains(text, "proc_") {
		t.Errorf("expected binary and process ID in list output, got:\n%s", text)
	}
	if strings.Contains(text, "other-daemon") {
		t.Errorf("list output must be filtered to barzakh-server, got:\n%s", text)
	}
}

func TestBZServerStop_UnknownProcessID(t *testing.T) {
	mgr := newBZServerManager(t)
	result, err := NewServerStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_does_not_exist"}))
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

func TestBZServerStatus_UnknownProcessID(t *testing.T) {
	mgr := newBZServerManager(t)
	result, err := NewServerStatus(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_missing"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Test: barzakh_server_start rejects invalid input
// ---------------------------------------------------------------------------

func TestBZServerStart_RejectsInvalidInput(t *testing.T) {
	mgr := newBZServerManager(t)
	tool := NewServerStart(mgr)
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
		{"missing data_dir", `{}`, "data_dir is required"},
		{"port zero", `{"data_dir":"` + dir + `","port":0}`, "port must be 1-65535"},
		{"port negative", `{"data_dir":"` + dir + `","port":-1}`, "port must be 1-65535"},
		{"port too large", `{"data_dir":"` + dir + `","port":70000}`, "port must be 1-65535"},
		{"bind not loopback", `{"data_dir":"` + dir + `","bind":"10.0.0.5"}`, "does not support custom bind addresses"},
		{"bind garbage", `{"data_dir":"` + dir + `","bind":"not-an-ip"}`, "does not support custom bind addresses"},
		{"api_key metachar", `{"data_dir":"` + dir + `","api_key":"abc;rm -rf /"}`, "forbidden character"},
		{"scan_root does not exist", `{"data_dir":"` + dir + `","scan_root":"/nonzero/firmware"}`, "not accessible"},
		{"scan_root is a file", `{"data_dir":"` + dir + `","scan_root":"` + fileWhereDirNeeded + `"}`, "must be a directory"},
		{"data_dir metachar", `{"data_dir":"/tmp/state;evil"}`, "forbidden character"},
		{"data_dir is a file", `{"data_dir":"` + fileWhereDirNeeded + `"}`, "not a directory"},
		{"bad json", `{invalid`, "invalid input"},
		{"wrong type", `{"data_dir":123}`, "invalid input"},
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
// barzakh-server refuses to start it.
func TestBZServerStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewServerStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"data_dir": t.TempDir(),
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

// Every shell metacharacter in the state directory is rejected before the
// daemon is launched.
func TestBZServerStart_DataDirMetacharInjection(t *testing.T) {
	mgr := newBZServerManager(t)
	tool := NewServerStart(mgr)
	for _, char := range shellMetachars {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"data_dir": "/tmp/state" + char + "evil",
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
