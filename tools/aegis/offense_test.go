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

// newOffenseTestManager builds a BackgroundManager whose
// "aegis-shadow-offense" allowlist entry points at a fake daemon script
// that sleeps until killed.
func newOffenseTestManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-aegis-offense")
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"aegis-shadow-offense": bin},
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
		"aegis_offense_start":  false,
		"aegis_offense_stop":   false,
		"aegis_offense_status": false,
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

	startDesc := NewOffenseStart(mgr).Description()
	for _, want := range []string{"Requires root/eBPF", "high-impact", "Approval-gated", "opt-in", "dead-man switch", "wipe_bytecode"} {
		if !strings.Contains(startDesc, want) {
			t.Errorf("aegis_offense_start description must mention %q", want)
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

	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"features":        []string{"memfd", "kprobe-evasion", "memfd"},
		"iface":           "eth1",
		"hide_pid":        4242,
		"obfuscate_inode": 999,
		"monitor_tty":     "136:0",
		"spoof_ppid":      "1234:1",
		"timestomp":       "1000:1:2:3",
		"pin_maps":        true,
		"verbose":         true,
		"logs_dir":        logsDir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{"HIGH IMPACT", "Process ID:** proc_", "PID:**", "aegis_offense_stop", "aegis_offense_status", logsDir, "```json", `"process_id":"proc_`} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}
	// No destructive flags requested: no destructive warning block.
	if strings.Contains(text, "DESTRUCTIVE FEATURES ACTIVE") {
		t.Errorf("unexpected destructive warning for a non-destructive launch, got:\n%s", text)
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
	if st.Binary != "aegis-shadow-offense" {
		t.Errorf("unexpected binary %q", st.Binary)
	}
	args := strings.Join(st.Args, " ")
	for _, want := range []string{"--enable-memfd", "--enable-kprobe-evasion", "--iface eth1", "--hide-pid 4242", "--obfuscate-inode 999", "--monitor-tty 136:0", "--spoof-ppid 1234:1", "--timestomp 1000:1:2:3", "--pin-maps", "--verbose"} {
		if !strings.Contains(args, want) {
			t.Errorf("expected %q in daemon args, got: %s", want, args)
		}
	}
	// Duplicated feature names dedupe to one flag.
	if strings.Count(args, "--enable-memfd") != 1 {
		t.Errorf("expected deduplicated feature flags, got: %s", args)
	}
	// Destructive flags stay absent by default.
	if strings.Contains(args, "--enable-deadman-switch") || strings.Contains(args, "--wipe-bytecode") {
		t.Errorf("destructive flags must be omitted by default, got: %s", args)
	}

	// Output files follow the aegis-offense-<id> naming scheme.
	if st.StdoutPath == "" || !strings.HasSuffix(st.StdoutPath, ".log") || !strings.Contains(st.StdoutPath, "aegis-offense-") {
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

func TestOffenseStart_Defaults(t *testing.T) {
	mgr := newOffenseTestManager(t)
	result, err := NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
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
	// Default interface is passed explicitly.
	if !strings.Contains(args, "--iface eth0") {
		t.Errorf("expected default --iface eth0, got: %s", args)
	}
	// Optional flags are omitted when unset, destructive flags included.
	for _, unwanted := range []string{"--hide-pid", "--obfuscate-inode", "--monitor-tty", "--spoof-ppid", "--timestomp", "--pin-maps", "--verbose", "--enable-deadman-switch", "--wipe-bytecode", "--enable-"} {
		if strings.Contains(args, unwanted) {
			t.Errorf("optional flag %q must be omitted when unset, got: %s", unwanted, args)
		}
	}
	if strings.Contains(result.Content[0].Text, "DESTRUCTIVE FEATURES ACTIVE") {
		t.Errorf("no destructive warning expected by default, got:\n%s", result.Content[0].Text)
	}
	if _, err := NewOffenseStop(mgr).Execute(context.Background(), mustJSON(map[string]any{"process_id": st.ID})); err != nil {
		t.Errorf("cleanup stop failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: destructive features are opt-in and loudly warned
// ---------------------------------------------------------------------------

func TestOffenseStart_DeadmanSwitchParam(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"features":       []string{"memfd"},
		"deadman_switch": true,
		"logs_dir":       t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--enable-deadman-switch") {
		t.Errorf("expected --enable-deadman-switch in daemon args, got: %s", args)
	}
	if strings.Contains(args, "--wipe-bytecode") {
		t.Errorf("--wipe-bytecode must stay omitted, got: %s", args)
	}

	text := result.Content[0].Text
	for _, want := range []string{"DESTRUCTIVE FEATURES ACTIVE", "deadman-switch: scorched-earth wipe triggers on tamper/timeout", "Use only on disposable, snapshotted lab VMs"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}
	if strings.Contains(text, "wipe-bytecode:") {
		t.Errorf("wipe-bytecode bullet must not appear when only deadman_switch is set, got:\n%s", text)
	}
}

func TestOffenseStart_WipeBytecodeParam(t *testing.T) {
	mgr := newOffenseTestManager(t)
	result, err := NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"wipe_bytecode": true,
		"logs_dir":      t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--wipe-bytecode") {
		t.Errorf("expected --wipe-bytecode in daemon args, got: %s", args)
	}
	if strings.Contains(args, "--enable-deadman-switch") {
		t.Errorf("--enable-deadman-switch must stay omitted, got: %s", args)
	}

	text := result.Content[0].Text
	for _, want := range []string{"DESTRUCTIVE FEATURES ACTIVE", "wipe-bytecode: eBPF bytecode is wiped from memory after load"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in start output, got:\n%s", want, text)
		}
	}
}

func TestOffenseStart_BothDestructiveFlags(t *testing.T) {
	mgr := newOffenseTestManager(t)
	result, err := NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
		"deadman_switch": true,
		"wipe_bytecode":  true,
		"logs_dir":       t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if !strings.Contains(args, "--enable-deadman-switch") || !strings.Contains(args, "--wipe-bytecode") {
		t.Errorf("expected both destructive flags, got: %s", args)
	}

	text := result.Content[0].Text
	if strings.Contains(text, "deadman-switch: scorched-earth wipe") && strings.Contains(text, "wipe-bytecode: eBPF bytecode is wiped") {
		// both bullets present
	} else {
		t.Errorf("expected both destructive bullets in warning, got:\n%s", text)
	}
}

// deadman-switch requested through the features list validates like any
// other feature, passes the flag exactly once (even together with the
// deadman_switch bool) and triggers the destructive warning.
func TestOffenseStart_DeadmanSwitchViaFeatures(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"features":       []string{"deadman-switch", "memfd", "deadman-switch"},
		"deadman_switch": true, // must not duplicate the flag
		"logs_dir":       t.TempDir(),
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("features entry \"deadman-switch\" must validate, got error: %s", result.Content[0].Text)
	}

	st := firstProcess(t, mgr)
	args := strings.Join(st.Args, " ")
	if strings.Count(args, "--enable-deadman-switch") != 1 {
		t.Errorf("expected exactly one --enable-deadman-switch, got: %s", args)
	}
	if !strings.Contains(result.Content[0].Text, "DESTRUCTIVE FEATURES ACTIVE") {
		t.Errorf("expected destructive warning when deadman-switch is in features, got:\n%s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: aegis_offense_start rejects invalid input
// ---------------------------------------------------------------------------

func TestOffenseStart_RejectsInvalidInput(t *testing.T) {
	mgr := newOffenseTestManager(t)
	tool := NewOffenseStart(mgr)
	dir := t.TempDir()
	fileWhereDirNeeded := writeTempFile(t, "not-a-dir", "x")

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing logs_dir", `{}`, "logs_dir is required"},
		{"unknown feature", `{"logs_dir":"` + dir + `","features":["format-disk"]}`, "unknown offense feature"},
		{"feature with metachar", `{"logs_dir":"` + dir + `","features":["memfd;rm -rf /"]}`, "forbidden character"},
		{"too many features", `{"logs_dir":"` + dir + `","features":["netns-hide","bpf-cloak","module-mask","memfd","syslog-strip","icmp-exfil","socket-clone","cred-relay","container-probe","kprobe-evasion","tail-calls","ftrace-blind","bpf-iter-abuse","vdso-hook","shm-covert","uffd-inject","coredump-suppress","isn-covert","ipv6-ext","arp-poison","port-knock","bgp-hijack","dr-abuse","pmc-covert","tsc-sidechan","audit-kill","inode-slack","journal-manip","proc-spoof","initramfs","modsign-bypass","polymorphic","phantom-stack","container-lateral","dma-covert","behavioral-ai","supply-chain","bpf-parasitism","kernel-object","network-stealth","persistence2","deadman-switch","extra-feature"]}`, "at most 42"},
		{"iface metachar", `{"logs_dir":"` + dir + `","iface":"eth0;evil"}`, "forbidden character"},
		{"iface not a name", `{"logs_dir":"` + dir + `","iface":"eth 0"}`, "invalid iface"},
		{"hide_pid zero", `{"logs_dir":"` + dir + `","hide_pid":0}`, "hide_pid"},
		{"hide_pid negative", `{"logs_dir":"` + dir + `","hide_pid":-1}`, "hide_pid"},
		{"obfuscate_inode zero", `{"logs_dir":"` + dir + `","obfuscate_inode":0}`, "obfuscate_inode"},
		{"monitor_tty bad", `{"logs_dir":"` + dir + `","monitor_tty":"136-0"}`, "invalid monitor_tty"},
		{"spoof_ppid bad", `{"logs_dir":"` + dir + `","spoof_ppid":"1234"}`, "invalid spoof_ppid"},
		{"timestomp bad", `{"logs_dir":"` + dir + `","timestomp":"1000:1:2"}`, "invalid timestomp"},
		{"logs_dir metachar", `{"logs_dir":"/tmp/x;evil"}`, "forbidden character"},
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

	// Unknown-feature errors must enumerate the real feature set.
	result, _ := tool.Execute(context.Background(), mustJSON(map[string]any{"logs_dir": dir, "features": []string{"nope"}}))
	if !strings.Contains(result.Content[0].Text, "netns-hide") || !strings.Contains(result.Content[0].Text, "persistence2") || !strings.Contains(result.Content[0].Text, "deadman-switch") {
		t.Errorf("expected valid feature list (incl. deadman-switch) in error, got: %s", result.Content[0].Text)
	}
}

// The binary must be allowlisted; a manager that does not know
// aegis-shadow-offense refuses to start it.
func TestOffenseStart_BinaryNotAllowed(t *testing.T) {
	mgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"some-other-binary": "/bin/true"},
	})
	result, err := NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{
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
			"logs_dir": "/tmp/offense" + char + "evil",
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
	if !strings.Contains(result.Content[0].Text, "No managed aegis-shadow-offense processes") {
		t.Errorf("expected empty-list message, got:\n%s", result.Content[0].Text)
	}

	// Start one daemon of each binary; the offense status list shows only
	// the offense loader.
	result, _ = NewDefenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"alerts_dir": t.TempDir()}))
	if result.IsError {
		t.Fatalf("defense start failed: %s", result.Content[0].Text)
	}
	result, _ = NewOffenseStart(mgr).Execute(context.Background(), mustJSON(map[string]any{"logs_dir": t.TempDir()}))
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
	if !strings.Contains(text, "aegis-shadow-offense") || !strings.Contains(text, "proc_") {
		t.Errorf("expected offense binary and process ID in list output, got:\n%s", text)
	}
	if strings.Contains(text, "aegis-shadow-defense") {
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
