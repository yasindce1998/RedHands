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

// newOffenseTestManager builds a BackgroundManager whose
// "staticzero-offense" allowlist entry points at a fake daemon script that
// sleeps until killed.
func newOffenseTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-staticzero-offense")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"staticzero-offense": bin},
	})
}

// newDualTestManager allowlists both the defense and offense fake daemons so
// binary-filtered status listing can be tested.
func newDualTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	allowed := map[string]string{}
	for _, name := range []string{defenseBinary, offenseBinary} {
		bin := filepath.Join(dir, "fake-"+name)
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 300\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		allowed[name] = bin
	}
	return executor.NewBackgroundManager(executor.Config{AllowedBinaries: allowed})
}

func offenseBgTools(mgr *executor.BackgroundManager) []mcp.Tool {
	return []mcp.Tool{
		NewOffenseStart(mgr),
		NewOffenseStop(mgr),
		NewOffenseStatus(mgr),
	}
}

// ---------------------------------------------------------------------------
// Test: offense lifecycle tool names, descriptions, schemas
// ---------------------------------------------------------------------------

func TestOffenseLifecycleTools_NameDescriptionSchema(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tools := offenseBgTools(mgr)

	wantNames := map[string]bool{
		"telecom_offense_start":  false,
		"telecom_offense_stop":   false,
		"telecom_offense_status": false,
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

	startDesc := NewOffenseStart(mgr).Description()
	for _, want := range []string{"root", "5.15", "F89-F172", "regulated", "Approval-gated", "high-impact"} {
		if !strings.Contains(startDesc, want) {
			t.Errorf("telecom_offense_start description must mention %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: successful start, output files, stop, status
// ---------------------------------------------------------------------------

func TestOffenseStart_SuccessLifecycle(t *testing.T) {
	mgr := newOffenseTestManager(t)
	start := NewOffenseStart(mgr)
	stop := NewOffenseStop(mgr)
	status := NewOffenseStatus(mgr)

	dir := t.TempDir()
	logsDir := filepath.Join(dir, "nested", "offense") // must be created 0700
	bpfObject := filepath.Join(dir, "custom.bpf.o")
	if err := os.WriteFile(bpfObject, []byte("ELF..."), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"groups":          []string{"telecom", "satellite", "telecom"},
		"target_imsi":     "460001234567890",
		"bpf_path":        bpfObject,
		"gtp_iface":       "gtp9",
		"ims_iface":       "ims0",
		"wifi_iface":      "wlan0",
		"sbi_iface":       "sbi0",
		"sdr_iface":       "sdr0",
		"sat_iface":       "sat0",
		"wpan_iface":      "wpan0",
		"uav_iface":       "uav0",
		"fronthaul_iface": "fh0",
		"logs_dir":        logsDir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"HIGH IMPACT", "Process ID:** proc_", "PID:**", "telecom_offense_stop", "telecom_offense_status", logsDir, "```json", `"process_id":"proc_`} {
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
	if st.Binary != "staticzero-offense" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{
		"--enable-telecom", "--enable-satellite",
		"--target-imsi 460001234567890",
		"--bpf-path " + bpfObject,
		"--gtp-iface gtp9", "--ims-iface ims0", "--wifi-iface wlan0", "--sbi-iface sbi0",
		"--sdr-iface sdr0", "--sat-iface sat0", "--wpan-iface wpan0", "--uav-iface uav0",
		"--fronthaul-iface fh0",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	// Duplicated group names dedupe to one flag.
	if strings.Count(args, "--enable-telecom") != 1 {
		t.Errorf("expected deduplicated group flags, got: %s", args)
	}
	if strings.Contains(args, "--all") {
		t.Errorf("explicit groups must not pass --all, got: %s", args)
	}

	// Output files follow the staticzero-offense-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".log") || !strings.Contains(st.StdoutPath, "staticzero-offense-") {
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

func TestOffenseStart_DefaultsAndAll(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)

	// all=true maps to --all; gtp_iface defaults to gtp0 and is always passed.
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"all":      true,
		"logs_dir": t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--all") {
		t.Errorf("expected --all, got: %s", args)
	}
	if !strings.Contains(args, "--gtp-iface gtp0") {
		t.Errorf("expected default --gtp-iface gtp0, got: %s", args)
	}
	if strings.Contains(args, "--enable-") || strings.Contains(args, "--target-imsi") || strings.Contains(args, "--bpf-path") || strings.Contains(args, "--ims-iface") {
		t.Errorf("optional flags must be omitted when unset, got: %s", args)
	}
	if _, err := NewOffenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: telecom_offense_start rejects invalid input
// ---------------------------------------------------------------------------

func TestOffenseStart_RejectsInvalidInput(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)
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
		{"missing logs_dir", `{"groups":["telecom"]}`, "logs_dir is required"},
		{"no groups and no all", `{"logs_dir":"` + dir + `"}`, "select at least one feature group or all"},
		{"empty groups and no all", `{"logs_dir":"` + dir + `","groups":[]}`, "select at least one feature group or all"},
		{"invalid group", `{"logs_dir":"` + dir + `","groups":["telecom-quantum"]}`, "invalid group"},
		{"imsi too short", `{"logs_dir":"` + dir + `","groups":["telecom"],"target_imsi":"46000123456789"}`, "15 digits"},
		{"imsi with letters", `{"logs_dir":"` + dir + `","groups":["telecom"],"target_imsi":"4600012345678ab"}`, "15 digits"},
		{"imsi with metachar", `{"logs_dir":"` + dir + `","groups":["telecom"],"target_imsi":"46000123456;890"}`, "forbidden character"},
		{"bpf_path does not exist", `{"logs_dir":"` + dir + `","groups":["telecom"],"bpf_path":"/nonzero/custom.bpf.o"}`, "not accessible"},
		{"gtp_iface metachar", `{"logs_dir":"` + dir + `","groups":["telecom"],"gtp_iface":"gtp0;evil"}`, "forbidden character"},
		{"gtp_iface not a name", `{"logs_dir":"` + dir + `","groups":["telecom"],"gtp_iface":"gtp 0"}`, "invalid gtp_iface"},
		{"ims_iface not a name", `{"logs_dir":"` + dir + `","groups":["telecom"],"ims_iface":"ims|0"}`, "forbidden character"},
		{"wifi_iface too long", `{"logs_dir":"` + dir + `","groups":["telecom"],"wifi_iface":"wlan000000000000000"}`, "invalid wifi_iface"},
		{"logs_dir metachar", `{"groups":["telecom"],"logs_dir":"/tmp/logs;evil"}`, "forbidden character"},
		{"logs_dir is a file", `{"groups":["telecom"],"logs_dir":"` + fileWhereDirNeeded + `"}`, "not a directory"},
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

// IMSI format boundaries: 15 digits accepted, 14 rejected, letters rejected.
func TestOffenseStart_IMSIValidation(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"groups":      []string{"telecom"},
		"target_imsi": "460001234567890",
		"logs_dir":    t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("15-digit IMSI must be accepted, got: %s", result.Content[0].Text)
	}
	st := firstProcess(t, mgr)
	if !strings.Contains(strings.Join(st.Args, " "), "--target-imsi 460001234567890") {
		t.Errorf("expected --target-imsi in daemon args, got: %v", st.Args)
	}
	if _, err := NewOffenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}

	for _, imsi := range []string{"46000123456789", "4600012345678ab", "4600012345678901"} {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"groups":      []string{"telecom"},
			"target_imsi": imsi,
			"logs_dir":    t.TempDir(),
		}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Errorf("IMSI %q must be rejected", imsi)
		} else if !strings.Contains(result.Content[0].Text, "15 digits") {
			t.Errorf("expected 15-digits error for IMSI %q, got: %s", imsi, result.Content[0].Text)
		}
	}
}

// The binary must be allowlisted; a manager that does not know
// staticzero-offense refuses to start it.
func TestOffenseStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"groups":   []string{"telecom"},
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
func TestOffenseStart_LogsDirMetacharInjection(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)
	for _, char := range shellMetachars {
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"groups":   []string{"telecom"},
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

// ---------------------------------------------------------------------------
// Test: status listing is filtered to the offense binary
// ---------------------------------------------------------------------------

func TestOffenseStatus_ListsOnlyOffenseProcesses(t *testing.T) {
	mgr := newDualTestManager(t)
	status := NewOffenseStatus(mgr)

	// Empty filtered list is fine.
	result, err := status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No managed staticzero-offense processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// Start one daemon of each binary; the offense status list shows only
	// the offense loader.
	result, _ = NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"logs_dir": t.TempDir()}))
	if result.IsError {
		t.Fatalf("defense start failed: %s", result.Content[0].Text)
	}
	result, _ = NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"groups": []string{"telecom"}, "logs_dir": t.TempDir()}))
	if result.IsError {
		t.Fatalf("offense start failed: %s", result.Content[0].Text)
	}

	result, err = status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected status error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "staticzero-offense") || !strings.Contains(text, "proc_") {
		t.Errorf("expected offense binary and process ID in list output, got:\n%s", text)
	}
	if strings.Contains(text, "staticzero-defense") {
		t.Errorf("offense status list must not show defense processes, got:\n%s", text)
	}
	if strings.Count(text, "### proc_") != 1 {
		t.Errorf("expected exactly one listed process, got:\n%s", text)
	}
}

func TestOffenseStop_UnknownProcessID(t *testing.T) {
	mgr := newOffenseTestManager(t)
	result, err := NewOffenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_does_not_exist"}))
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

func TestOffenseStatus_UnknownProcessID(t *testing.T) {
	mgr := newOffenseTestManager(t)
	result, err := NewOffenseStatus(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": "proc_missing"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].Text, "unknown process") {
		t.Errorf("expected unknown-process error, got: %+v", result)
	}
}
