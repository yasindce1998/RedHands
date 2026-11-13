package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/workflow"
	"github.com/yasindce1998/redhands/tools/kubedagger"
)

// Golden record-rule → targetdb tests. Unlike recorder_test.go (synthetic
// payloads), these feed fixtures captured from (or derived strictly from the
// output structs of) the real binaries through the CampaignRecorder with the
// playbooks' actual record rules, proving the whole chain: binary output
// shape → wrapper fence → campaign extraction → record rules → targetdb.
// Fixture provenance is documented in each testdata/<toolset>/README.md.

func loadGoldenFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return data
}

func loadPlaybook(t *testing.T, name string) *workflow.Template {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "playbooks", name))
	if err != nil {
		t.Fatalf("reading playbook: %v", err)
	}
	var tpl workflow.Template
	if err := json.Unmarshal(data, &tpl); err != nil {
		t.Fatalf("parsing playbook: %v", err)
	}
	return &tpl
}

func decodeGolden(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("decoding fixture JSON: %v", err)
	}
	return value
}

// recordFixtureWithRules runs one step's record rules from a real playbook
// against a fixture document, mirroring EnhancedEngine.recordStep's
// extraction (StructuredFromText on the wrapper-shaped markdown, then
// lookupPath per rule).
func recordFixtureWithRules(t *testing.T, rec *CampaignRecorder, workflowID, stepID, tool string, fixture []byte, rules []workflow.RecordRule, mitre []string) int {
	t.Helper()
	wrapperText := "## Golden Step\n\n```json\n" + strings.TrimSpace(string(fixture)) + "\n```\n"
	raw, ok := workflow.StructuredFromText(wrapperText)
	if !ok {
		t.Fatalf("campaign extractor could not pull fixture JSON out of the wrapper-shaped markdown")
	}
	value := decodeGolden(t, raw)

	recorded := 0
	for _, rule := range rules {
		pathValue, ok := workflow.LookupPathValue(value, rule.Path)
		if !ok {
			t.Errorf("record rule path %q does not resolve against the fixture (output-shape drift)", rule.Path)
			continue
		}
		items, ok := pathValue.([]any)
		if !ok {
			t.Errorf("record rule path %q is not an array in the fixture", rule.Path)
			continue
		}
		if len(items) == 0 {
			continue
		}
		if err := rec.RecordStep(workflowID, stepID, tool, rule, items, mitre); err != nil {
			t.Errorf("RecordStep(%s %q) failed: %v", rule.Type, rule.Path, err)
			continue
		}
		recorded += len(items)
	}
	return recorded
}

// TestRecorderGolden_K8sReconChainRulesAgainstClusterReport feeds the
// ClusterReport fixture through the k8s-recon-chain playbook's actual
// discover-step record rules and asserts the targetdb contents.
func TestRecorderGolden_K8sReconChainRulesAgainstClusterReport(t *testing.T) {
	playbook := loadPlaybook(t, "k8s-recon-chain.json")
	discover := findPlaybookStep(t, playbook, "discover")

	db := targetdb.NewStore("", false)
	rec := NewCampaignRecorder(db)

	fixture := loadGoldenFixture(t, "kubedagger", "cluster-report.json")
	recorded := recordFixtureWithRules(t, rec, "golden-k8s", "discover", "kubedagger_k8s_discover", fixture, discover.Record, discover.MITRE)

	// 3 nodes + 3 pods must land as hosts.
	if recorded != 6 {
		t.Fatalf("expected 6 recorded items (3 nodes + 3 pods), got %d", recorded)
	}
	if got := len(db.ListHosts()); got != 6 {
		t.Fatalf("expected 6 hosts in targetdb, got %d", got)
	}

	// Node rule: {ip: ip, hostname: name, os: os}.
	node, ok := db.GetHost("192.0.2.10")
	if !ok {
		t.Fatal("node 192.0.2.10 not recorded")
	}
	if node.Hostname != "lab-control-plane-0" || node.OS != "Ubuntu 22.04.3 LTS" {
		t.Errorf("node mapping wrong: %+v", node)
	}
	if len(node.Tags) != 1 || node.Tags[0] != "campaign:golden-k8s" {
		t.Errorf("node campaign tag wrong: %+v", node.Tags)
	}

	// Pod rule: {ip: pod_ip, hostname: name} — the field-name mapping that
	// would break if the ClusterReport struct renamed pod_ip.
	pod, ok := db.GetHost("10.244.1.23")
	if !ok {
		t.Fatal("pod 10.244.1.23 not recorded via pod_ip mapping")
	}
	if pod.Hostname != "debug-toolbox-7f9c8d6e5-x1y2z" {
		t.Errorf("pod mapping wrong: %+v", pod)
	}
	if _, ok := db.GetHost("10.244.0.10"); !ok {
		t.Error("pod 10.244.0.10 not recorded")
	}
	if _, ok := db.GetHost("10.244.2.31"); !ok {
		t.Error("pod 10.244.2.31 not recorded")
	}
}

// TestRecorderGolden_BarzakhFindingsAgainstRealScan feeds the real
// barzakh-scanner 0.7.0 ScanResult fixture through a finding record rule
// using the "findings" path and asserts severities/titles land in the
// targetdb (lowercased, MITRE-enriched).
func TestRecorderGolden_BarzakhFindingsAgainstRealScan(t *testing.T) {
	db := targetdb.NewStore("", false)
	rec := NewCampaignRecorder(db)

	fixture := loadGoldenFixture(t, "barzakh", "scan-malicious-blacklotus.json")
	rule := workflow.RecordRule{
		Type: "finding",
		Path: "findings",
		Fields: map[string]string{
			"severity":    "severity",
			"title":       "title",
			"description": "description",
		},
	}
	recorded := recordFixtureWithRules(t, rec, "golden-fw", "scan", "barzakh_scan", fixture, []workflow.RecordRule{rule}, []string{"T1595.002"})

	var scan struct {
		Findings []struct {
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(fixture, &scan); err != nil {
		t.Fatalf("fixture is not the 0.7.0 ScanResult envelope: %v", err)
	}
	if recorded != len(scan.Findings) {
		t.Fatalf("expected %d recorded findings, got %d", len(scan.Findings), recorded)
	}

	findings := db.ListFindings()
	if len(findings) != len(scan.Findings) {
		t.Fatalf("expected %d findings in targetdb, got %d", len(scan.Findings), len(findings))
	}
	severityCount := map[string]int{}
	for _, f := range findings {
		severityCount[f.Severity]++
		if f.Tool != "barzakh_scan" {
			t.Errorf("finding tool wrong: %+v", f)
		}
		if f.Host != "unknown" {
			t.Errorf("scan findings carry no host; expected \"unknown\", got %q", f.Host)
		}
		if len(f.MITRE) != 1 || f.MITRE[0] != "T1595.002" {
			t.Errorf("finding MITRE enrichment wrong: %v", f.MITRE)
		}
	}
	// The real capture: 2 critical, 1 high, 3 medium.
	if severityCount["critical"] != 2 || severityCount["high"] != 1 || severityCount["medium"] != 3 {
		t.Errorf("severity accounting against the real capture drifted: %v", severityCount)
	}
	if scan.Findings[0].Severity != "critical" {
		t.Errorf("fixture order assumption broken; update severity expectations")
	}
}

// TestRecorderGolden_LegacyBarzakhArrayCannotBeRecorded documents the drift
// for environments pinned to barzakh-scanner <= 0.6: the legacy stdout is a
// bare top-level findings array, and no record-rule path can select the
// root document, so recording is skipped (the engine appends a "path not
// found" warning to the step result). Pinned so a future envelope change on
// either side is conscious.
func TestRecorderGolden_LegacyBarzakhArrayCannotBeRecorded(t *testing.T) {
	fixture := loadGoldenFixture(t, "barzakh", "scan-malicious-blacklotus-v05.json")
	value := decodeGolden(t, fixture)
	if _, ok := workflow.LookupPathValue(value, "findings"); ok {
		t.Log("legacy fixture now carries a findings envelope; this drift documentation can be removed")
	}
	// The array itself still resolves via numeric indexing, so a
	// hypothetical wrapper re-enveloping the legacy output would fix
	// recording without touching record rules.
	if _, ok := workflow.LookupPathValue(value, "0.severity"); !ok {
		t.Error("numeric paths into the legacy findings array stopped resolving")
	}
}

// TestCampaignEndToEndGolden_K8sReconChainPlaybook runs the real shipped
// k8s-recon-chain playbook end to end: the real kubedagger_k8s_discover
// wrapper (fed the ClusterReport fixture bytes through a mock executor),
// the real playbook file loaded from playbooks/, the campaign engine's
// template instantiation, structured extraction, record rules, and the
// CampaignRecorder — then asserts the targetdb contents.
func TestCampaignEndToEndGolden_K8sReconChainPlaybook(t *testing.T) {
	report := loadGoldenFixture(t, "kubedagger", "cluster-report.json")

	srv := mcp.NewServer("test", "1")
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		if strings.Contains(strings.Join(args, " "), "k8s discover") {
			return report
		}
		return nil
	}
	for _, tool := range []mcp.Tool{
		kubedagger.NewK8sDiscover(mock),
		kubedagger.NewSAToken(mock),
		kubedagger.NewK8sAbuse(mock),
		kubedagger.NewMITREExport(mock),
		kubedagger.NewDetection(mock),
	} {
		if err := srv.RegisterTool(tool); err != nil {
			t.Fatalf("registering %s: %v", tool.Name(), err)
		}
	}

	// Serve the real playbook from a template dir.
	templateDir := t.TempDir()
	playbookPath := filepath.Join("..", "..", "playbooks", "k8s-recon-chain.json")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("reading playbook: %v", err)
	}
	if err := os.WriteFile(filepath.Join(templateDir, "k8s-recon-chain.json"), data, 0o600); err != nil {
		t.Fatalf("staging playbook: %v", err)
	}

	db := targetdb.NewStore("", false)
	cfg := &config.Config{WorkflowStateDir: t.TempDir(), WorkflowTemplateDir: templateDir, WorkflowMaxParallel: 2}
	SetupCampaign(srv, cfg, db, nil)

	runResp := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"campaign/run","params":{"id":"golden-k8s-e2e","template":"k8s-recon-chain"}}`))
	if runResp == nil || !strings.Contains(string(runResp), `"success":true`) {
		t.Fatalf("campaign run failed: %s", runResp)
	}

	// All 6 discovered hosts (3 nodes + 3 pods) must be in the targetdb,
	// tagged with the campaign id.
	if got := len(db.ListHosts()); got != 6 {
		t.Fatalf("expected 6 recorded hosts from the ClusterReport fixture, got %d", got)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "10.244.0.10", "10.244.1.23", "10.244.2.31"} {
		host, ok := db.GetHost(ip)
		if !ok {
			t.Errorf("host %s not recorded", ip)
			continue
		}
		if len(host.Tags) != 1 || host.Tags[0] != "campaign:golden-k8s-e2e" {
			t.Errorf("host %s campaign tag wrong: %+v", ip, host.Tags)
		}
	}
	// Field mapping through the whole chain: node hostname/os survive.
	node, ok := db.GetHost("192.0.2.12")
	if !ok || node.Hostname != "lab-worker-1" || node.OS != "Flatcar Container Linux 3602.0.0" {
		t.Errorf("node 192.0.2.12 mapping wrong through the full pipeline: %+v", node)
	}
	pod, ok := db.GetHost("10.244.1.23")
	if !ok || pod.Hostname != "debug-toolbox-7f9c8d6e5-x1y2z" {
		t.Errorf("pod 10.244.1.23 mapping wrong through the full pipeline: %+v", pod)
	}
}

func findPlaybookStep(t *testing.T, tpl *workflow.Template, stepID string) workflow.EnhancedStep {
	t.Helper()
	for _, step := range tpl.Steps {
		if step.ID == stepID {
			return step
		}
	}
	t.Fatalf("step %q not found in playbook %q", stepID, tpl.Name)
	return workflow.EnhancedStep{}
}
