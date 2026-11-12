package aegis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func allTools() []mcp.Tool { return Tools() }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sampleNDJSON mirrors the defense::AlertRecord schema: 5 valid records and
// 1 malformed line.
const sampleNDJSON = `{"timestamp":1000000000,"alert_type":"Ghost Map Detected","severity":"LOW","pid":100,"context":5,"details":"map_id=5, suspicious_ops=1","anomaly_score":0.5,"correlated_types":[],"is_attack_chain":false}
{"timestamp":2000000000,"alert_type":"Syscall Latency Anomaly","severity":"MEDIUM","pid":200,"context":59,"details":"syscall=59, latency=800000ns","anomaly_score":1.5,"correlated_types":[],"is_attack_chain":false}
this line is not json
{"timestamp":3000000000,"alert_type":"Memory-Backed Execution","severity":"CRITICAL","pid":300,"context":3,"details":"fd=3, pid=300","anomaly_score":12.5,"correlated_types":["Memory-Backed Execution","BPF Map C2 Signature"],"is_attack_chain":true}
{"timestamp":4000000000,"alert_type":"BPF Map C2 Signature","severity":"HIGH","pid":300,"context":7,"details":"map_id=7, violations=2","anomaly_score":7.0,"correlated_types":["Memory-Backed Execution","BPF Map C2 Signature"],"is_attack_chain":true}
{"timestamp":5000000000,"alert_type":"Hidden Process Detected","severity":"HIGH","pid":400,"context":900,"details":"hidden_pid=900, parent=1","anomaly_score":3.0,"correlated_types":[],"is_attack_chain":false}
`

// ---------------------------------------------------------------------------
// Test: all tools have unique names, compliant descriptions, valid schemas
// ---------------------------------------------------------------------------

func TestAllTools_NameDescriptionSchema(t *testing.T) {
	tools := allTools()
	if len(tools) != 6 {
		t.Fatalf("expected 6 aegis tools, got %d", len(tools))
	}
	seen := make(map[string]bool)
	for _, tool := range tools {
		name := tool.Name()
		desc := tool.Description()
		if name == "" || !strings.HasPrefix(name, "aegis_") {
			t.Errorf("tool name %q must be prefixed with aegis_", name)
		}
		if seen[name] {
			t.Errorf("duplicate tool name: %q", name)
		}
		seen[name] = true

		if !strings.Contains(desc, "Aegis-Shadow") || !strings.Contains(desc, "authorized lab") {
			t.Errorf("tool %q description must mention Aegis-Shadow and authorized lab use", name)
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
}

// ---------------------------------------------------------------------------
// Test: static catalog matches the Aegis-Shadow sources
// ---------------------------------------------------------------------------

func TestCatalogMatchesSource(t *testing.T) {
	if len(defenseModules) != 15 {
		t.Fatalf("expected 15 defense modules, got %d", len(defenseModules))
	}
	seenFlags := map[string]bool{}
	for i, m := range defenseModules {
		if m.Number != i+1 {
			t.Errorf("defense module %q has number %d, expected %d", m.Flag, m.Number, i+1)
		}
		if !strings.HasPrefix(m.Flag, "--") || strings.Contains(m.Flag, "_") {
			t.Errorf("defense module flag %q must be a dashed CLI flag", m.Flag)
		}
		if seenFlags[m.Flag] {
			t.Errorf("duplicate defense module flag %q", m.Flag)
		}
		seenFlags[m.Flag] = true
		if m.HookPoint == "" || m.AlertType == "" || m.Description == "" {
			t.Errorf("defense module %q has empty catalog fields", m.Flag)
		}
	}

	if len(offenseFeatures) != 44 {
		t.Fatalf("expected 44 offense feature flags, got %d", len(offenseFeatures))
	}
	seenNames := map[string]bool{}
	for _, f := range offenseFeatures {
		if !strings.HasPrefix(f.Flag, "--enable-") || strings.Contains(f.Flag, "_") {
			t.Errorf("offense feature flag %q must be a dashed --enable-* flag", f.Flag)
		}
		if f.Name == "" || offenseFeatureByName[f.Name].Flag != f.Flag {
			t.Errorf("offense feature %q is not indexed correctly", f.Name)
		}
		if seenNames[f.Name] {
			t.Errorf("duplicate offense feature name %q", f.Name)
		}
		seenNames[f.Name] = true
		if f.Risk == "" || f.HookPoint == "" || f.ID == "" {
			t.Errorf("offense feature %q has empty catalog fields", f.Name)
		}
	}

	// Spot-check flags verified directly against the sources.
	for _, flag := range []string{"--ghost-maps", "--syscall-latency", "--bytecode-check", "--hidden-process", "--suspicious-hooks", "--prog-inventory", "--syscall-anomaly", "--net-baseline", "--memfd-detect", "--map-audit", "--tracepoint-monitor", "--cross-reference", "--hw-perf-counters", "--verifier-analysis", "--memory-forensics"} {
		if !seenFlags[flag] {
			t.Errorf("defense module flag %s missing from catalog", flag)
		}
	}
	for _, name := range []string{"enable_netns_hide", "enable_memfd", "enable_bpf_cloak", "enable_deadman_switch", "enable_kernel_object", "enable_network_stealth", "enable_persistence2"} {
		if !seenNames[name] {
			t.Errorf("offense feature %s missing from catalog", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: aegis_alerts_parse filtering and summary
// ---------------------------------------------------------------------------

func TestAlertsParse_FiltersAndSummary(t *testing.T) {
	path := writeTempFile(t, "alerts.ndjson", sampleNDJSON)
	tool := NewAlertsParse()

	cases := []struct {
		name    string
		params  string
		wantSub []string
	}{
		{
			name:    "no filter",
			params:  `{"file":"` + path + `"}`,
			wantSub: []string{"Matching alerts:** 5", "skipped malformed lines: 1", "Memory-Backed Execution", "Attack-chain alerts:** 2"},
		},
		{
			name:    "severity floor HIGH",
			params:  `{"file":"` + path + `","severity":"HIGH"}`,
			wantSub: []string{"Matching alerts:** 3", "severity >= HIGH"},
		},
		{
			name:    "severity floor CRITICAL",
			params:  `{"file":"` + path + `","severity":"CRITICAL"}`,
			wantSub: []string{"Matching alerts:** 1"},
		},
		{
			name:    "attack chains only",
			params:  `{"file":"` + path + `","only_attack_chains":true}`,
			wantSub: []string{"Matching alerts:** 2", "attack chains only"},
		},
		{
			name:    "min anomaly score",
			params:  `{"file":"` + path + `","min_anomaly_score":5.0}`,
			wantSub: []string{"Matching alerts:** 2", "anomaly_score >= 5.00"},
		},
		{
			name:    "combined filters",
			params:  `{"file":"` + path + `","severity":"MEDIUM","min_anomaly_score":7.0}`,
			wantSub: []string{"Matching alerts:** 2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tool.Execute(context.Background(), json.RawMessage(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
			}
			text := result.Content[0].Text
			for _, want := range tc.wantSub {
				if !strings.Contains(text, want) {
					t.Errorf("expected %q in output, got:\n%s", want, text)
				}
			}
			if !strings.Contains(text, "```json") {
				t.Error("expected a JSON block with full matching records")
			}
		})
	}
}

func TestAlertsParse_RejectsInvalidInput(t *testing.T) {
	path := writeTempFile(t, "alerts.ndjson", sampleNDJSON)
	tool := NewAlertsParse()

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing file param", `{}`, "file is required"},
		{"nonexistent file", `{"file":"/nonexistent/aegis-alerts.ndjson"}`, "does not exist"},
		{"directory as file", `{"file":"` + t.TempDir() + `"}`, "directory"},
		{"invalid severity", `{"file":"` + path + `","severity":"loud"}`, "invalid severity"},
		{"negative anomaly score", `{"file":"` + path + `","min_anomaly_score":-1}`, "min_anomaly_score"},
		{"malformed json", `{invalid`, "invalid input"},
		{"wrong type", `{"file":123}`, "invalid input"},
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

func TestAlertsParse_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "empty.ndjson", "")
	result, err := NewAlertsParse().Execute(context.Background(), mustJSON(map[string]any{"file": path}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("empty file should not be an error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No matching alerts") {
		t.Errorf("expected 'No matching alerts', got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: aegis_alerts_tail
// ---------------------------------------------------------------------------

func TestAlertsTail_LastN(t *testing.T) {
	path := writeTempFile(t, "alerts.ndjson", sampleNDJSON)
	tool := NewAlertsTail()

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"file": path, "count": 2}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "Matching alerts:** 2") {
		t.Errorf("expected 2 matching alerts, got:\n%s", text)
	}
	if !strings.Contains(text, "last 2 of 5") {
		t.Errorf("expected scope note 'last 2 of 5', got:\n%s", text)
	}
	// The last two records are pid 300 (BPF Map C2 Signature) and pid 400.
	if !strings.Contains(text, "BPF Map C2 Signature") || !strings.Contains(text, "Hidden Process Detected") {
		t.Errorf("expected the two most recent alerts, got:\n%s", text)
	}
	// Earlier alerts must not be rendered.
	if strings.Contains(text, "Ghost Map Detected") {
		t.Errorf("first alert should not appear in a tail of 2, got:\n%s", text)
	}
}

func TestAlertsTail_DefaultCountAndSeverity(t *testing.T) {
	path := writeTempFile(t, "alerts.ndjson", sampleNDJSON)
	tool := NewAlertsTail()

	// Default count (20) covers all 5 alerts.
	result, _ := tool.Execute(context.Background(), mustJSON(map[string]any{"file": path}))
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Matching alerts:** 5") {
		t.Errorf("expected all 5 alerts with default count, got:\n%s", result.Content[0].Text)
	}

	// Severity floor applied before tailing.
	result, _ = tool.Execute(context.Background(), mustJSON(map[string]any{"file": path, "count": 10, "severity": "CRITICAL"}))
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Matching alerts:** 1") {
		t.Errorf("expected 1 CRITICAL alert, got:\n%s", result.Content[0].Text)
	}
}

func TestAlertsTail_RejectsInvalidInput(t *testing.T) {
	path := writeTempFile(t, "alerts.ndjson", sampleNDJSON)
	tool := NewAlertsTail()

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"negative count", `{"file":"` + path + `","count":-1}`, "positive integer"},
		{"count too large", `{"file":"` + path + `","count":501}`, "at most 500"},
		{"nonexistent file", `{"file":"/nonexistent/x.ndjson"}`, "does not exist"},
		{"invalid severity", `{"file":"` + path + `","severity":"extreme"}`, "invalid severity"},
		{"missing file", `{}`, "file is required"},
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

// ---------------------------------------------------------------------------
// Test: aegis_modules_list
// ---------------------------------------------------------------------------

func TestModulesList_Catalog(t *testing.T) {
	tool := NewModulesList()

	result, err := tool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || result.IsError {
		t.Fatalf("unexpected result: %+v %v", result, err)
	}
	text := result.Content[0].Text
	for _, want := range []string{"--ghost-maps", "--memory-forensics", "--enable-memfd", "--enable-persistence2", "aegis-shadow-defense", "aegis-shadow-offense", "is_attack_chain"} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in full catalog, got:\n%s", want, text)
		}
	}

	result, _ = tool.Execute(context.Background(), mustJSON(map[string]any{"component": "defense"}))
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text = result.Content[0].Text
	if !strings.Contains(text, "--ghost-maps") || strings.Contains(text, "--enable-memfd") {
		t.Errorf("defense filter wrong: expected defense modules only")
	}

	result, _ = tool.Execute(context.Background(), mustJSON(map[string]any{"component": "offense"}))
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text = result.Content[0].Text
	if !strings.Contains(text, "--enable-memfd") || strings.Contains(text, "--ghost-maps") {
		t.Errorf("offense filter wrong: expected offense features only")
	}

	result, _ = tool.Execute(context.Background(), mustJSON(map[string]any{"component": "bogus"}))
	if !result.IsError {
		t.Error("expected error for invalid component")
	}
}

// ---------------------------------------------------------------------------
// Test: aegis_defense_config_write / aegis_defense_config_read
// ---------------------------------------------------------------------------

func TestDefenseConfigWrite_AndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defense-config.json")
	writeTool := NewDefenseConfigWrite()
	readTool := NewDefenseConfigRead()

	result, err := writeTool.Execute(context.Background(), mustJSON(map[string]any{
		"path": path, "threshold": 3, "window_secs": 45,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"threshold":3,"window_secs":45}` {
		t.Fatalf("unexpected config content: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}

	result, err = readTool.Execute(context.Background(), mustJSON(map[string]any{"path": path}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "Threshold:** 3") || !strings.Contains(text, "Correlation window:** 45 seconds") {
		t.Errorf("unexpected read output:\n%s", text)
	}
}

func TestDefenseConfigWrite_DefaultsAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := NewDefenseConfigWrite().Execute(context.Background(), mustJSON(map[string]any{"path": path}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"threshold":2,"window_secs":30}` {
		t.Fatalf("expected engine defaults, got: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected existing file to be tightened to 0600, got %v", info.Mode().Perm())
	}
}

func TestDefenseConfigWrite_RejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	tool := NewDefenseConfigWrite()

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"threshold too high", `{"path":"` + filepath.Join(dir, "c.json") + `","threshold":5}`, "threshold must be"},
		{"threshold too low", `{"path":"` + filepath.Join(dir, "c.json") + `","threshold":-1}`, "threshold must be"},
		{"window too large", `{"path":"` + filepath.Join(dir, "c.json") + `","window_secs":90000}`, "window_secs"},
		{"window negative", `{"path":"` + filepath.Join(dir, "c.json") + `","window_secs":-5}`, "window_secs"},
		{"missing path", `{}`, "path is required"},
		{"path is directory", `{"path":"` + dir + `"}`, "directory"},
		{"bad json", `{invalid`, "invalid input"},
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

func TestDefenseConfigRead_ValidatesContent(t *testing.T) {
	dir := t.TempDir()
	tool := NewDefenseConfigRead()

	// Missing fields fall back to engine defaults.
	path := writeTempFile(t, "partial.json", `{"threshold":4}`)
	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"path": path}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "Threshold:** 4") || !strings.Contains(text, "Correlation window:** 30 seconds") {
		t.Errorf("expected defaults for missing fields, got:\n%s", text)
	}

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"malformed json", `{not json`, "invalid config JSON"},
		{"threshold out of range", `{"threshold":9,"window_secs":30}`, "invalid threshold"},
		{"window out of range", `{"threshold":2,"window_secs":0}`, "invalid window_secs"},
		{"wrong type", `{"threshold":"high"}`, "invalid config JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, "cfg.json", tc.content)
			result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"path": path}))
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

	result, _ = tool.Execute(context.Background(), mustJSON(map[string]any{"path": filepath.Join(dir, "missing.json")}))
	if !result.IsError || !strings.Contains(result.Content[0].Text, "does not exist") {
		t.Errorf("expected missing-file error, got: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// Test: aegis_offense_plan (dry-run planner)
// ---------------------------------------------------------------------------

func TestOffensePlan_ValidPlan(t *testing.T) {
	tool := NewOffensePlan()

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"features": []string{"enable_memfd", "--enable-bpf-cloak"},
		"iface":    "eth0",
		"hide_pid": 1337,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	for _, want := range []string{
		"DRY RUN",
		"nothing was executed",
		"sudo ./offense --enable-memfd --enable-bpf-cloak --iface eth0 --hide-pid 1337",
		"Fileless execution",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in plan output, got:\n%s", want, text)
		}
	}
	// Both normalized spellings must dedupe to a single flag in the command line.
	commandLine := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "sudo ./offense ") {
			commandLine = line
		}
	}
	if commandLine == "" {
		t.Fatalf("no command line rendered in plan output:\n%s", text)
	}
	if strings.Count(commandLine, "--enable-memfd") != 1 {
		t.Errorf("expected exactly one --enable-memfd flag in the command, got: %s", commandLine)
	}
}

func TestOffensePlan_OptionValidation(t *testing.T) {
	tool := NewOffensePlan()
	base := map[string]any{"features": []string{"enable_memfd"}}

	valid := []map[string]any{
		{"monitor_tty": "136:0"},
		{"spoof_ppid": "10:1"},
		{"timestomp": "100:1700000000:1700000001:1700000002"},
		{"obfuscate_inode": 42},
		{"pin_maps": true},
		{"wipe_bytecode": true},
	}
	for _, extra := range valid {
		params := map[string]any{"features": base["features"]}
		for k, v := range extra {
			params[k] = v
		}
		result, err := tool.Execute(context.Background(), mustJSON(params))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if result.IsError {
			t.Errorf("expected success for %v, got: %s", extra, result.Content[0].Text)
		}
	}

	invalid := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"bad tty", map[string]any{"monitor_tty": "abc"}, "invalid monitor_tty"},
		{"bad spoof", map[string]any{"spoof_ppid": "10:1:2"}, "invalid spoof_ppid"},
		{"bad timestomp", map[string]any{"timestomp": "100:1:2"}, "invalid timestomp"},
		{"bad iface", map[string]any{"iface": "eth 0"}, "invalid iface"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"features": []string{"enable_memfd"}}
			for k, v := range tc.extra {
				params[k] = v
			}
			result, err := tool.Execute(context.Background(), mustJSON(params))
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

	// High-impact options must be called out.
	result, _ := tool.Execute(context.Background(), mustJSON(map[string]any{
		"features":      []string{"enable_memfd"},
		"wipe_bytecode": true,
		"pin_maps":      true,
	}))
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "High-impact options") || !strings.Contains(text, "--wipe-bytecode") || !strings.Contains(text, "--pin-maps") {
		t.Errorf("expected high-impact option warnings, got:\n%s", text)
	}
}

func TestOffensePlan_RejectsInvalidFeatures(t *testing.T) {
	tool := NewOffensePlan()

	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"missing features", `{}`, "features is required"},
		{"empty features", `{"features":[]}`, "features is required"},
		{"null features", `{"features":null}`, "features is required"},
		{"unknown feature", `{"features":["enable_format_disk"]}`, "unknown offense feature \"enable_format_disk\""},
		{"wrong type", `{"features":"enable_memfd"}`, "invalid input"},
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

	// Unknown-feature errors must enumerate the real flag set.
	result, _ := tool.Execute(context.Background(), mustJSON(map[string]any{"features": []string{"nope"}}))
	if !strings.Contains(result.Content[0].Text, "enable_netns_hide") || !strings.Contains(result.Content[0].Text, "enable_persistence2") {
		t.Errorf("expected valid feature list in error, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: shell metacharacter injection is rejected everywhere
// ---------------------------------------------------------------------------

func TestShellMetacharRejection(t *testing.T) {
	forbiddenChars := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

	tests := []struct {
		name   string
		tool   mcp.Tool
		params func(injection string) json.RawMessage
	}{
		{
			name: "AlertsParse_file",
			tool: NewAlertsParse(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"file": "/tmp/alerts.ndjson" + inj + "evil"})
			},
		},
		{
			name: "AlertsTail_file",
			tool: NewAlertsTail(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"file": "/tmp/alerts.ndjson" + inj + "evil"})
			},
		},
		{
			name: "ConfigRead_path",
			tool: NewDefenseConfigRead(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"path": "/tmp/cfg.json" + inj + "evil"})
			},
		},
		{
			name: "ConfigWrite_path",
			tool: NewDefenseConfigWrite(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"path": "/tmp/cfg.json" + inj + "evil", "threshold": 2})
			},
		},
		{
			name: "OffensePlan_iface",
			tool: NewOffensePlan(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"features": []string{"enable_memfd"}, "iface": "eth0" + inj + "bad"})
			},
		},
		{
			name: "OffensePlan_timestomp",
			tool: NewOffensePlan(),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"features": []string{"enable_memfd"}, "timestomp": "1:2:3:4" + inj + "x"})
			},
		},
	}

	for _, tc := range tests {
		for _, char := range forbiddenChars {
			t.Run(tc.name+"_char_"+charLabel(char), func(t *testing.T) {
				result, err := tc.tool.Execute(context.Background(), tc.params(char))
				if err != nil {
					t.Fatalf("Execute returned Go error: %v", err)
				}
				if !result.IsError {
					t.Errorf("expected rejection for char %q, but got success", char)
					return
				}
				// All these fields reject metachars with either the shared
				// forbidden-character error or a strict format error.
				msg := result.Content[0].Text
				if !strings.Contains(msg, "forbidden character") && !strings.Contains(msg, "invalid iface") && !strings.Contains(msg, "invalid timestomp") {
					t.Errorf("expected metachar rejection in error, got: %s", msg)
				}
			})
		}
	}
}

// Offense feature names containing metachars can never match the catalog.
func TestOffensePlan_FeatureInjectionRejected(t *testing.T) {
	for _, inj := range []string{"enable_memfd; rm -rf /", "enable_memfd$(id)", "enable_memfd`id`"} {
		result, err := NewOffensePlan().Execute(context.Background(), mustJSON(map[string]any{"features": []string{inj}}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Fatalf("expected rejection for feature %q", inj)
		}
		if !strings.Contains(result.Content[0].Text, "unknown offense feature") && !strings.Contains(result.Content[0].Text, "forbidden character") {
			t.Errorf("expected unknown-feature rejection, got: %s", result.Content[0].Text)
		}
	}
}

// charLabel returns a readable label for metacharacters used in test names.
func charLabel(c string) string {
	labels := map[string]string{
		";": "semicolon", "|": "pipe", "&": "ampersand", "`": "backtick",
		"$": "dollar", "(": "lparen", ")": "rparen", "{": "lbrace", "}": "rbrace",
		"<": "lt", ">": "gt", "!": "bang", "'": "squote", "\"": "dquote",
		"\\": "backslash", "\n": "newline", "\r": "carriage_return",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return c
}
