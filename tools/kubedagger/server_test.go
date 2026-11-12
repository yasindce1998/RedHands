package kubedagger

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

// newKDServerManager builds a BackgroundManager whose "kubedagger-server"
// allowlist entry points at a fake daemon script that sleeps until killed.
func newKDServerManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-kubedagger-server")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"kubedagger-server": bin},
	})
}

// kdFirstProcess returns the managed process with the latest start time. The
// manager keeps stopped processes in its list, so tests that start more than
// one daemon use this to get the newest.
func kdFirstProcess(t *testing.T, mgr *executor.BackgroundManager) executor.BackgroundStatus {
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

func TestKDServerLifecycleTools_NameDescriptionSchema(t *testing.T) {
	mgr := newKDServerManager(t)
	tools := []mcp.Tool{NewServerStart(mgr), NewServerStop(mgr), NewServerStatus(mgr)}

	wantNames := map[string]bool{
		"kubedagger_server_start":  false,
		"kubedagger_server_stop":   false,
		"kubedagger_server_status": false,
	}
	for _, tool := range tools {
		name := tool.Name()
		if _, ok := wantNames[name]; !ok {
			t.Errorf("unexpected tool name %q", name)
			continue
		}
		wantNames[name] = true

		desc := tool.Description()
		if !strings.Contains(desc, "KubeDagger") {
			t.Errorf("tool %q description must mention KubeDagger", name)
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
	for _, want := range []string{"HIGH IMPACT", "approval-gated", "C2", "kubedagger-server"} {
		if !strings.Contains(startDesc, want) {
			t.Errorf("kubedagger_server_start description must mention %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: successful start, output files, stop, status
// ---------------------------------------------------------------------------

func TestKDServerStart_SuccessLifecycle(t *testing.T) {
	mgr := newKDServerManager(t)
	start := NewServerStart(mgr)
	stop := NewServerStop(mgr)
	status := NewServerStatus(mgr)

	dir := t.TempDir()
	eventsDir := filepath.Join(dir, "nested", "events") // must be created 0700
	scope := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(scope, []byte("namespaces: [demo]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malleable := filepath.Join(dir, "malleable.yaml")
	if err := os.WriteFile(malleable, []byte("name: lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"events_dir": eventsDir,
		"scope":      scope,
		"malleable":  malleable,
		"webui":      "127.0.0.1:8080",
		"rate_limit": 10.5,
		"psk":        "test-psk-123",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{
		"Process ID:** proc_", "PID:**", "kubedagger_server_stop", "kubedagger_server_status",
		eventsDir, "```json", `"process_id":"proc_`, `"events_path":`, "HIGH IMPACT",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}
	// The PSK is redacted in the rendered command echo.
	if !strings.Contains(text, "--psk <redacted>") || strings.Contains(text, "test-psk-123") {
		t.Errorf("expected redacted PSK in start output, got:\n%s", text)
	}

	// The output directory was created with 0700.
	info, err := os.Stat(eventsDir)
	if err != nil {
		t.Fatalf("events_dir not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 directory, got %v", info.Mode().Perm())
	}

	// Exactly one managed process, running, with the expected args and files.
	st := kdFirstProcess(t, mgr)
	if !st.Running || st.PID <= 0 {
		t.Fatalf("expected running process, got %+v", st)
	}
	if st.Binary != "kubedagger-server" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{
		"--events", ".events.jsonl",
		"--scope " + scope, "--malleable " + malleable,
		"--webui 127.0.0.1:8080", "--rate-limit 10.5", "--psk REDACTED",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	if !strings.HasPrefix(st.StdoutPath, eventsDir) {
		t.Errorf("stdout path %q must live under events_dir %q", st.StdoutPath, eventsDir)
	}

	// Output files follow the kubedagger-server-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".log") || !strings.Contains(st.StdoutPath, "kubedagger-server-") {
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
	// The generated --events file path points inside events_dir.
	eventsFlag := ""
	for i, a := range st.Args {
		if a == "--events" && i+1 < len(st.Args) {
			eventsFlag = st.Args[i+1]
		}
	}
	if !strings.HasPrefix(eventsFlag, eventsDir) || !strings.HasSuffix(eventsFlag, ".events.jsonl") {
		t.Errorf("unexpected --events path %q", eventsFlag)
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

func TestKDServerStart_Defaults(t *testing.T) {
	mgr := newKDServerManager(t)
	tool := NewServerStart(mgr)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"events_dir": t.TempDir()}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	st := kdFirstProcess(t, mgr)
	if len(st.Args) != 2 || st.Args[0] != "--events" {
		t.Errorf("expected only --events <path> defaults, got: %v", st.Args)
	}
	if _, err := NewServerStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

func TestKDServerStatus_ListsFilteredProcesses(t *testing.T) {
	dir := t.TempDir()
	otherBin := filepath.Join(dir, "fake-other-daemon")
	if err := os.WriteFile(otherBin, []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{
			"kubedagger-server": filepath.Join(dir, "fake-kubedagger-server"),
			"other-daemon":      otherBin,
		},
	})
	if err := os.WriteFile(filepath.Join(dir, "fake-kubedagger-server"), []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
		t.Fatal(err)
	}
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
	if !strings.Contains(result.Content[0].Text, "No managed kubedagger-server processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// With a kubedagger-server process, the list shows it but not the other daemon.
	result, _ = NewServerStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"events_dir": t.TempDir()}))
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
	if !strings.Contains(text, "kubedagger-server") || !strings.Contains(text, "proc_") {
		t.Errorf("expected binary and process ID in list output, got:\n%s", text)
	}
	if strings.Contains(text, "other-daemon") {
		t.Errorf("list output must be filtered to kubedagger-server, got:\n%s", text)
	}
}

func TestKDServerStop_UnknownProcessID(t *testing.T) {
	mgr := newKDServerManager(t)
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

func TestKDServerStatus_UnknownProcessID(t *testing.T) {
	mgr := newKDServerManager(t)
	result, err := NewServerStatus(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_missing"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Test: kubedagger_server_start rejects invalid input
// ---------------------------------------------------------------------------

func TestKDServerStart_RejectsInvalidInput(t *testing.T) {
	mgr := newKDServerManager(t)
	tool := NewServerStart(mgr)
	dir := t.TempDir()
	fileWhereDirNeeded := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fileWhereDirNeeded, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	scopeDir := filepath.Join(dir, "scope-as-dir") // a directory where a file is required
	if err := os.MkdirAll(scopeDir, 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing events_dir", `{}`, "events_dir is required"},
		{"scope does not exist", `{"events_dir":"` + dir + `","scope":"/nonzero/scope.yaml"}`, "not accessible"},
		{"scope is a directory", `{"events_dir":"` + dir + `","scope":"` + scopeDir + `"}`, "must be a file"},
		{"malleable does not exist", `{"events_dir":"` + dir + `","malleable":"/nonzero/mall.yaml"}`, "not accessible"},
		{"webui missing port", `{"events_dir":"` + dir + `","webui":"127.0.0.1"}`, "host:port"},
		{"webui zero port", `{"events_dir":"` + dir + `","webui":"127.0.0.1:0"}`, "invalid port"},
		{"webui port too large", `{"events_dir":"` + dir + `","webui":"127.0.0.1:70000"}`, "invalid port"},
		{"rate limit negative", `{"events_dir":"` + dir + `","rate_limit":-5}`, "rate_limit"},
		{"rate limit zero", `{"events_dir":"` + dir + `","rate_limit":0}`, "rate_limit"},
		{"rate limit too large", `{"events_dir":"` + dir + `","rate_limit":100001}`, "rate_limit"},
		{"psk metachar", `{"events_dir":"` + dir + `","psk":"abc;rm -rf /"}`, "forbidden character"},
		{"events_dir metachar", `{"events_dir":"/tmp/logs;evil"}`, "forbidden character"},
		{"events_dir is a file", `{"events_dir":"` + fileWhereDirNeeded + `"}`, "not a directory"},
		{"bad json", `{invalid`, "invalid input"},
		{"wrong type", `{"events_dir":123}`, "invalid input"},
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
// kubedagger-server refuses to start it.
func TestKDServerStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewServerStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"events_dir": t.TempDir(),
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
func TestKDServerStart_EventsDirMetacharInjection(t *testing.T) {
	mgr := newKDServerManager(t)
	tool := NewServerStart(mgr)
	for _, char := range shellMetachars {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"events_dir": "/tmp/logs" + char + "evil",
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
