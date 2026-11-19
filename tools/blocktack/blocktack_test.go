package blocktack

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

// newBlocktackManager builds a BackgroundManager whose "blocktack" binary
// is a trivial script that stays alive until killed, mirroring the telecom
// test scaffolding.
func newBlocktackManager(t *testing.T) *executor.BackgroundManager {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-blocktack")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 300\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: map[string]string{"blocktack": bin},
		MaxOutputBytes:  1024 * 1024,
	})
}

func mustJSON(v map[string]any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func TestCatalog_NameDescriptionSchema(t *testing.T) {
	cases := []struct {
		tool mcp.Tool
		name string
	}{
		{NewCapabilities(nil), "blocktack_capabilities"},
		{NewMatrix(nil), "blocktack_matrix"},
		{NewValidateTarget(nil), "blocktack_validate_target"},
		{NewRecon(nil), "blocktack_recon"},
		{NewScan(nil), "blocktack_scan"},
		{NewNodeAudit(nil), "blocktack_node_audit"},
		{NewEngineCall(nil), "blocktack_engine_call"},
		{NewCampaignResults(), "blocktack_campaign_results"},
		{NewReport(nil), "blocktack_report"},
	}
	for _, tc := range cases {
		if tc.tool.Name() != tc.name {
			t.Errorf("tool name = %q, want %q", tc.tool.Name(), tc.name)
		}
		var schema map[string]any
		if err := json.Unmarshal(tc.tool.InputSchema(), &schema); err != nil {
			t.Errorf("tool %q schema is not valid JSON: %v", tc.name, err)
		}
		if schema["type"] != "object" {
			t.Errorf("tool %q schema must be an object", tc.name)
		}
		if !strings.Contains(tc.tool.Description(), "BlockTack") {
			t.Errorf("tool %q description must mention BlockTack", tc.name)
		}
	}

	mgr := newBlocktackManager(t)
	for _, tc := range []struct {
		tool mcp.Tool
		name string
	}{
		{NewCampaignStart(mgr, nil), "blocktack_campaign_start"},
		{NewCampaignStop(mgr), "blocktack_campaign_stop"},
		{NewCampaignStatus(mgr), "blocktack_campaign_status"},
	} {
		if tc.tool.Name() != tc.name {
			t.Errorf("tool name = %q, want %q", tc.tool.Name(), tc.name)
		}
		var schema map[string]any
		if err := json.Unmarshal(tc.tool.InputSchema(), &schema); err != nil {
			t.Errorf("tool %q schema is not valid JSON: %v", tc.name, err)
		}
	}
}

func TestCapabilities_AndMatrix(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		if binary == "blocktack" && len(args) > 0 && args[0] == "capabilities" {
			return []byte(`{"version":"0.1.0","root":"/opt/blocktack","engines":[{"name":"blocktack-evm","present":true}],"adapters":["slither","foundry"]}`)
		}
		if binary == "blocktack" && len(args) > 0 && args[0] == "matrix" {
			return []byte(`{"version":2,"layers":[{"id":"L2","name":"Contracts","weaknesses":[{"id":"BTV-L2-003","name":"Oracle dependency"}]}]}`)
		}
		return nil
	}

	result, err := NewCapabilities(mock).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || result.IsError {
		t.Fatalf("capabilities failed: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), `"version": "0.1.0"`) && !strings.Contains(resultText(result), `"version":"0.1.0"`) {
		t.Errorf("capabilities output missing version:\n%s", resultText(result))
	}
	// The child env must carry BLOCKTACK_ROOT and BLOCKTACK_JSON_ERRORS.
	call := mock.LastCall()
	env := strings.Join(call.Env, " ")
	if !strings.Contains(env, "BLOCKTACK_ROOT=") || !strings.Contains(env, "BLOCKTACK_JSON_ERRORS=1") {
		t.Errorf("capabilities call env missing BLOCKTACK_ROOT/JSON_ERRORS: %v", call.Env)
	}

	result, err = NewMatrix(mock).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || result.IsError {
		t.Fatalf("matrix failed: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), "BTV-L2-003") {
		t.Errorf("matrix output missing weakness:\n%s", resultText(result))
	}

	// Layer filter narrows; unknown weakness is a hard error.
	result, err = NewMatrix(mock).Execute(context.Background(), mustJSON(map[string]any{"layer": "L2"}))
	if err != nil || result.IsError {
		t.Fatalf("matrix layer filter failed: %v %s", err, resultText(result))
	}
	result, err = NewMatrix(mock).Execute(context.Background(), mustJSON(map[string]any{"weakness": "BTV-L9-999"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("unknown weakness filter must be an error")
	}
}

func TestValidateTarget_RefusalIsVerdict(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		return []byte(`{"valid":false,"target":"t.yaml","name":"t","chain":{"type":"evm","network":"local"},"guardrail":"expired_authorization","violations":["authorization expired"]}`)
	}
	mock.ErrFn = func(binary string, args []string) error {
		return &fakeExitError{code: 3}
	}

	result, err := NewValidateTarget(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("guardrail refusal must surface as the verdict, not a tool error: %s", resultText(result))
	}
	if !strings.Contains(resultText(result), "INVALID") || !strings.Contains(resultText(result), "expired_authorization") {
		t.Errorf("verdict must flag invalid + guardrail code:\n%s", resultText(result))
	}

	// Missing target file is rejected before any subprocess runs.
	result, err = NewValidateTarget(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/nonexistent/t.yaml"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("missing target file must be an error")
	}
}

func TestFindingsTools_ArgvAndRefusal(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		return []byte(`[{"id":"bt-1","severity":"critical","title":"Oracle manipulation"}]`)
	}

	// recon: --emit findings-json on stdout.
	result, err := NewRecon(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null"}))
	if err != nil || result.IsError {
		t.Fatalf("recon failed: %v %s", err, resultText(result))
	}
	call := mock.LastCall()
	joined := strings.Join(call.Args, " ")
	if !strings.Contains(joined, "recon --target /dev/null --emit findings-json") {
		t.Errorf("unexpected recon argv: %s", joined)
	}
	if !strings.Contains(resultText(result), "1 critical") {
		t.Errorf("recon summary missing severity counts:\n%s", resultText(result))
	}

	// scan: adapters validated and joined with commas.
	result, err = NewScan(mock).Execute(context.Background(), mustJSON(map[string]any{
		"target": "/dev/null", "adapters": []string{"slither", "foundry", "slither"},
	}))
	if err != nil || result.IsError {
		t.Fatalf("scan failed: %v %s", err, resultText(result))
	}
	joined = strings.Join(mock.LastCall().Args, " ")
	if !strings.Contains(joined, "--adapters slither,foundry") {
		t.Errorf("unexpected scan argv: %s", joined)
	}
	result, err = NewScan(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null", "adapters": []string{"echidna"}}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("unknown adapter must be an error")
	}

	// node-audit: module enum validated, web-audit/p2p-eclipse accepted.
	for _, module := range []string{"all", "web-audit", "p2p-eclipse", "cve-check"} {
		result, err = NewNodeAudit(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null", "module": module}))
		if err != nil || result.IsError {
			t.Fatalf("node-audit %s failed: %v %s", module, err, resultText(result))
		}
		if !strings.Contains(strings.Join(mock.LastCall().Args, " "), "--module "+module) {
			t.Errorf("node-audit argv missing module %s", module)
		}
	}
	result, err = NewNodeAudit(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null", "module": "quantum-audit"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("unknown module must be an error")
	}

	// Guardrail refusals (exit 3) render as a distinct refusal, with the
	// structured stderr error preferred.
	mock.StdoutFn = nil
	mock.ErrFn = func(binary string, args []string) error {
		return &fakeExitError{code: 3}
	}
	mock.ExitCodeFn = func(binary string, args []string) int { return 3 }
	mock.StderrFn = func(binary string, args []string) []byte {
		return []byte(`{"error":{"code":"unsafe_endpoint","message":"endpoint neither local nor listed","target":"t.yaml"}}`)
	}
	result, err = NewRecon(mock).Execute(context.Background(), mustJSON(map[string]any{"target": "/dev/null"}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(resultText(result), "unsafe_endpoint") {
		t.Errorf("exit 3 must render as a guardrail refusal:\n%s", resultText(result))
	}
}

func TestEngineCall_LoopbackOnly(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		return []byte(`[{"id":"e1","severity":"info","title":"chain id"}]`)
	}

	result, err := NewEngineCall(mock).Execute(context.Background(), mustJSON(map[string]any{
		"engine": "blocktack-evm", "action": "simulate-call",
		"rpc_url": "http://127.0.0.1:8545",
		"options": map[string]any{"to": "0xdead", "data": "0x00"},
	}))
	if err != nil || result.IsError {
		t.Fatalf("engine call failed: %v %s", err, resultText(result))
	}
	call := mock.LastCall()
	if call.Binary != "blocktack-evm" || len(call.Args) != 0 {
		t.Errorf("engine call must invoke the engine with no argv: %+v", call)
	}
	var job engineJob
	if err := json.Unmarshal(call.Stdin, &job); err != nil {
		t.Fatalf("stdin is not a valid job: %v", err)
	}
	if job.Action != "simulate-call" || job.Target.Endpoints[0].URL != "http://127.0.0.1:8545" {
		t.Errorf("unexpected job: %s", call.Stdin)
	}
	if !strings.Contains(resultText(result), "1 info") {
		t.Errorf("engine findings summary missing:\n%s", resultText(result))
	}

	// Non-loopback RPC is refused outright; localhost is accepted.
	for rpc, ok := range map[string]bool{
		"http://eth.drpc.org":     false,
		"http://example.com:8545": false,
		"http://localhost:8545":   true,
		"http://[::1]:8545":       true,
	} {
		result, err = NewEngineCall(mock).Execute(context.Background(), mustJSON(map[string]any{
			"engine": "blocktack-evm", "action": "fingerprint", "rpc_url": rpc,
		}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if ok && result.IsError {
			t.Errorf("loopback rpc %s must be accepted: %s", rpc, resultText(result))
		}
		if !ok && !result.IsError {
			t.Errorf("non-loopback rpc %s must be refused", rpc)
		}
	}

	// Unknown engine/action combos are rejected before any subprocess.
	result, err = NewEngineCall(mock).Execute(context.Background(), mustJSON(map[string]any{
		"engine": "blocktack-solana", "action": "map-oracles", "rpc_url": "http://127.0.0.1:8899",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("solana engine must reject evm-only actions")
	}
}

func TestCampaignLifecycle(t *testing.T) {
	mgr := newBlocktackManager(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	playbook := filepath.Join(dir, "pb.yaml")
	for _, f := range []string{target, playbook} {
		if err := os.WriteFile(f, []byte("name: x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Pre-flight validation gate: invalid verdict refuses the launch.
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		return []byte(`{"valid":false,"name":"t","chain":{"type":"evm","network":"local"},"violations":["authorization expired"]}`)
	}
	start := NewCampaignStart(mgr, mock)
	result, err := start.Execute(context.Background(), mustJSON(map[string]any{
		"target": target, "playbook": playbook, "out_dir": dir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(resultText(result), "validate-target") {
		t.Errorf("invalid target must refuse the launch:\n%s", resultText(result))
	}

	// Valid verdict launches the campaign with --progress-json.
	mock.StdoutFn = func(binary string, args []string) []byte {
		return []byte(`{"valid":true,"name":"t","chain":{"type":"evm","network":"local"},"endpoints":[{"role":"rpc","url":"http://127.0.0.1:8545"}]}`)
	}
	result, err = start.Execute(context.Background(), mustJSON(map[string]any{
		"target": target, "playbook": playbook, "out_dir": dir,
	}))
	if err != nil || result.IsError {
		t.Fatalf("campaign start failed: %v %s", err, resultText(result))
	}
	var started struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(result.StructuredContent, &started); err != nil || started.ProcessID == "" {
		t.Fatalf("start result must carry process_id in StructuredContent: %s", result.StructuredContent)
	}
	st := mgrListFirst(t, mgr)
	if st.Binary != "blocktack" || !st.Running {
		t.Fatalf("expected running blocktack process, got %+v", st)
	}
	joined := strings.Join(st.Args, " ")
	if !strings.Contains(joined, "campaign --target "+target) || !strings.Contains(joined, "--progress-json") {
		t.Errorf("unexpected campaign argv: %s", joined)
	}

	// A second concurrent campaign is refused (port collision guard).
	result, err = start.Execute(context.Background(), mustJSON(map[string]any{
		"target": target, "playbook": playbook, "out_dir": dir,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError || !strings.Contains(resultText(result), "cannot run concurrently") {
		t.Errorf("second concurrent campaign must be refused:\n%s", resultText(result))
	}

	// Status lists the campaign; process_id status reports running.
	status := NewCampaignStatus(mgr)
	result, err = status.Execute(context.Background(), mustJSON(map[string]any{"process_id": started.ProcessID}))
	if err != nil || result.IsError {
		t.Fatalf("campaign status failed: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), "RUNNING") {
		t.Errorf("status must report RUNNING:\n%s", resultText(result))
	}
	result, err = status.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil || result.IsError || !strings.Contains(resultText(result), started.ProcessID) {
		t.Errorf("status list must include the campaign:\n%s", resultText(result))
	}

	// Stop, then status shows exited; double stop is a no-op.
	stop := NewCampaignStop(mgr)
	result, err = stop.Execute(context.Background(), mustJSON(map[string]any{"process_id": started.ProcessID}))
	if err != nil || result.IsError {
		t.Fatalf("campaign stop failed: %v %s", err, resultText(result))
	}
	result, err = status.Execute(context.Background(), mustJSON(map[string]any{"process_id": started.ProcessID}))
	if err != nil || result.IsError {
		t.Fatalf("campaign status failed: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), "EXITED") {
		t.Errorf("status must report EXITED after stop:\n%s", resultText(result))
	}
	result, err = stop.Execute(context.Background(), mustJSON(map[string]any{"process_id": started.ProcessID}))
	if err != nil || result.IsError {
		t.Errorf("double stop must be a no-op: %v %s", err, resultText(result))
	}
}

func TestCampaignResults_ReadsRunDir(t *testing.T) {
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, "findings.json"), []byte(`[{"id":"f1","severity":"high","title":"drained"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "killchains.json"), []byte(`[{"id":"kc1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "status.json"), []byte(`{"state":"completed","findings_so_far":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := NewCampaignResults().Execute(context.Background(), mustJSON(map[string]any{"run_dir": runDir}))
	if err != nil || result.IsError {
		t.Fatalf("campaign results failed: %v %s", err, resultText(result))
	}
	text := resultText(result)
	for _, want := range []string{"1 high", "findings.json", "killchains.json", "completed"} {
		if !strings.Contains(text, want) {
			t.Errorf("results output missing %q:\n%s", want, text)
		}
	}
	if len(result.StructuredContent) == 0 {
		t.Errorf("results must expose findings as StructuredContent")
	}

	// Absent findings.json is reported, not an error (stopped campaign).
	empty := t.TempDir()
	result, err = NewCampaignResults().Execute(context.Background(), mustJSON(map[string]any{"run_dir": empty}))
	if err != nil || result.IsError {
		t.Fatalf("empty run dir must not error: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), "has not completed") {
		t.Errorf("empty run dir must explain missing findings:\n%s", resultText(result))
	}
}

func TestCampaignStatus_ParsesProgressAndRunDir(t *testing.T) {
	dir := t.TempDir()
	progress := filepath.Join(dir, "campaign-x.out")
	lines := []string{
		`{"event":"started","run_dir":"` + dir + `","target":"t","steps":3}`,
	}
	for i := 0; i < maxProgressTail; i++ {
		lines = append(lines, `{"event":"step_started","id":"filler-`+string(rune('a'+i))+`","step":1}`)
	}
	lines = append(lines,
		`{"event":"step_finished","id":"exploit","ok":true,"findings":2,"findings_total":2}`,
	)
	if err := os.WriteFile(progress, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := campaignRunDir(progress); got != dir {
		t.Errorf("campaignRunDir = %q, want %q", got, dir)
	}
	tail := campaignProgressTail(progress)
	if !strings.Contains(tail, `"exploit"`) || strings.Contains(tail, `"started"`) || strings.Contains(tail, "filler-a") {
		t.Errorf("progress tail must contain only the last events:\n%s", tail)
	}
}

func TestReportTool(t *testing.T) {
	dir := t.TempDir()
	findings := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(findings, []byte(`[{"id":"f1","severity":"high"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "report.md")

	mock := executor.NewMock()
	result, err := NewReport(mock).Execute(context.Background(), mustJSON(map[string]any{
		"findings": []string{findings}, "out": out, "engagement": true, "title": "Q4 Review",
	}))
	if err != nil || result.IsError {
		t.Fatalf("report failed: %v %s", err, resultText(result))
	}
	joined := strings.Join(mock.LastCall().Args, " ")
	for _, want := range []string{"report --findings " + findings, "--engagement", "--title Q4 Review"} {
		if !strings.Contains(joined, want) {
			t.Errorf("report argv missing %q: %s", want, joined)
		}
	}
	if err := os.WriteFile(out, []byte("# Report\n\nbody"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = NewReport(mock).Execute(context.Background(), mustJSON(map[string]any{
		"findings": []string{findings}, "out": out,
	}))
	if err != nil || result.IsError {
		t.Fatalf("report failed: %v %s", err, resultText(result))
	}
	if !strings.Contains(resultText(result), "# Report") {
		t.Errorf("report output must preview the markdown:\n%s", resultText(result))
	}

	// Missing findings file is rejected before any subprocess.
	result, err = NewReport(mock).Execute(context.Background(), mustJSON(map[string]any{
		"findings": []string{filepath.Join(dir, "missing.json")}, "out": out,
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Errorf("missing findings file must be an error")
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func resultText(r *mcp.ToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

func mgrListFirst(t *testing.T, mgr *executor.BackgroundManager) executor.BackgroundStatus {
	t.Helper()
	list := mgr.List()
	if len(list) == 0 {
		t.Fatal("no managed processes")
	}
	return list[0]
}

// fakeExitError satisfies the error interface the wrappers format; the
// executor Result carries the actual exit code in wrappers driven by the
// mock, so tests set ExitCode via StderrFn/ErrFn plus the result path.
type fakeExitError struct{ code int }

func (e *fakeExitError) Error() string { return "execution failed (exit 3)" }
