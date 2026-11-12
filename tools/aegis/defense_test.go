package aegis

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

// newTestManager builds a BackgroundManager whose "aegis-shadow-defense"
// allowlist entry points at a fake daemon script that sleeps until killed.
func newTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-aegis-defense")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"aegis-shadow-defense": bin},
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
		"aegis_defense_start":  false,
		"aegis_defense_stop":   false,
		"aegis_defense_status": false,
	}
	for _, tool := range tools {
		name := tool.Name()
		if _, ok := wantNames[name]; !ok {
			t.Errorf("unexpected tool name %q", name)
			continue
		}
		wantNames[name] = true

		desc := tool.Description()
		if !strings.Contains(desc, "Aegis-Shadow") {
			t.Errorf("tool %q description must mention Aegis-Shadow", name)
		}
		if !strings.Contains(desc, "authorized lab") {
			t.Errorf("tool %q description must mention authorized lab use", name)
		}
		if !strings.Contains(desc, "educational/VM-only") {
			t.Errorf("tool %q description must mention educational/VM-only", name)
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
	if !strings.Contains(startDesc, "Requires root/eBPF") || !strings.Contains(startDesc, "high-impact") {
		t.Error("aegis_defense_start description must mention root/eBPF requirement and high impact")
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
	alertsDir := filepath.Join(dir, "nested", "alerts") // must be created 0700
	config := writeTempFile(t, "defense-config.json", `{"threshold":3,"window_secs":45}`)

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"modules":            []string{"ghost-maps", "syscall-latency", "ghost-maps"},
		"threshold":          3,
		"calibration_period": 120,
		"config":             config,
		"enable_ml":          true,
		"alerts_dir":         alertsDir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"Process ID:** proc_", "PID:**", "aegis_defense_stop", "aegis_alerts_parse", alertsDir, "```json", `"process_id":"proc_`} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}

	// The output directory was created with 0700.
	info, err := os.Stat(alertsDir)
	if err != nil {
		t.Fatalf("alerts_dir not created: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 directory, got %v", info.Mode().Perm())
	}

	// Exactly one managed process, running, with the expected args and files.
	st := firstProcess(t, mgr)
	if !st.Running || st.PID <= 0 {
		t.Fatalf("expected running process, got %+v", st)
	}
	if st.Binary != "aegis-shadow-defense" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{"--ghost-maps", "--syscall-latency", "--json-stdout", "-t 3", "--calibration-period 120", "--config " + config, "--enable-ml"} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	if strings.Contains(args, "--all-modules") {
		t.Errorf("explicit modules must not pass --all-modules, got: %s", args)
	}
	// Duplicated module names dedupe to one flag.
	if strings.Count(args, "--ghost-maps") != 1 {
		t.Errorf("expected deduplicated module flags, got: %s", args)
	}

	// Output files are created next to the alert stream.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".ndjson") {
		t.Errorf("unexpected stdout path %q", st.StdoutPath)
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
	if !strings.Contains(text, "Running:** no") {
		t.Errorf("expected stopped status, got:\n%s", text)
	}
	for _, want := range []string{"Exit code:**", "Logs (stderr):**", st.StdoutPath} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in stopped status, got:\n%s", want, text)
		}
	}

	// Stopping an exited process is a no-op, not an error.
	result, _ = stop.Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID}))
	if result.IsError {
		t.Errorf("double stop should be a no-op, got: %s", result.Content[0].Text)
	}
}

func TestDefenseStart_EmptyModulesUsesAllModules(t *testing.T) {
	mgr := newTestManager(t)
	result, err := NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"alerts_dir": t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--all-modules") {
		t.Errorf("expected --all-modules for empty module list, got: %s", args)
	}
	if !strings.Contains(args, "--json-stdout") {
		t.Errorf("--json-stdout must always be present, got: %s", args)
	}
	if strings.Contains(args, "-t ") || strings.Contains(args, "--enable-ml") || strings.Contains(args, "--calibration-period") {
		t.Errorf("optional flags must be omitted when unset, got: %s", args)
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
	result, _ = NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"alerts_dir": t.TempDir()}))
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
	if !strings.Contains(text, "aegis-shadow-defense") || !strings.Contains(text, "proc_") {
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
// Test: aegis_defense_start rejects invalid input
// ---------------------------------------------------------------------------

func TestDefenseStart_RejectsInvalidInput(t *testing.T) {
	mgr := newTestManager(t)
	tool := NewDefenseStart(mgr)
	dir := t.TempDir()
	_ = writeTempFile(t, "cfg.json", `{"threshold":2}`)
	fileWhereDirNeeded := writeTempFile(t, "not-a-dir", "x")

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing alerts_dir", `{}`, "alerts_dir is required"},
		{"unknown module", `{"alerts_dir":"` + dir + `","modules":["format-disk"]}`, "unknown defense module"},
		{"module with metachar", `{"alerts_dir":"` + dir + `","modules":["ghost-maps;rm -rf /"]}`, "forbidden character"},
		{"too many modules", `{"alerts_dir":"` + dir + `","modules":["ghost-maps","syscall-latency","bytecode-check","hidden-process","suspicious-hooks","prog-inventory","syscall-anomaly","net-baseline","memfd-detect","map-audit","tracepoint-monitor","cross-reference","hw-perf-counters","verifier-analysis","memory-forensics","honeypots"]}`, "at most 15"},
		{"threshold too high", `{"alerts_dir":"` + dir + `","threshold":5}`, "threshold must be"},
		{"threshold too low", `{"alerts_dir":"` + dir + `","threshold":0}`, "threshold must be"},
		{"calibration negative", `{"alerts_dir":"` + dir + `","calibration_period":-5}`, "calibration_period"},
		{"calibration too large", `{"alerts_dir":"` + dir + `","calibration_period":100000}`, "calibration_period"},
		{"config does not exist", `{"alerts_dir":"` + dir + `","config":"/nonexistent/cfg.json"}`, "does not exist"},
		{"alerts_dir metachar", `{"alerts_dir":"/tmp/x;evil"}`, "forbidden character"},
		{"alerts_dir is a file", `{"alerts_dir":"` + fileWhereDirNeeded + `"}`, "not a directory"},
		{"bad json", `{invalid`, "invalid input"},
		{"wrong type", `{"alerts_dir":123}`, "invalid input"},
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

	// Valid module names at the bounds must be accepted.
	for _, threshold := range []int{1, 4} {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"modules":    []string{"memory-forensics"},
			"threshold":  threshold,
			"alerts_dir": t.TempDir(),
		}))
		if err != nil || result.IsError {
			t.Errorf("expected threshold %d to be accepted, got: %v %+v", threshold, err, result)
		}
	}

	// Unknown-module errors must enumerate the real module set.
	result, _ := tool.Execute(context.Background(), mustJSON(map[string]any{"alerts_dir": dir, "modules": []string{"nope"}}))
	if !strings.Contains(result.Content[0].Text, "ghost-maps") || !strings.Contains(result.Content[0].Text, "memory-forensics") {
		t.Errorf("expected valid module list in error, got: %s", result.Content[0].Text)
	}
}

// The binary must be allowlisted; a manager that does not know
// aegis-shadow-defense refuses to start it.
func TestDefenseStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"alerts_dir": t.TempDir(),
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
func TestDefenseStart_AlertsDirMetacharInjection(t *testing.T) {
	mgr := newTestManager(t)
	tool := NewDefenseStart(mgr)
	for _, char := range shellMetachars {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"alerts_dir": "/tmp/alerts" + char + "evil",
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
