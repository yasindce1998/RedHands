//go:build livee2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Scenario 1 (flagship, fully offline): the barzakh purple-team loop.
//
// barzakh_corpus (adversary generates a malicious/clean corpus into a temp
// dir) → barzakh_scan of one malicious sample (scanner exit 1 = bootkit
// detected must surface as a RESULT, with the severity summary rendered) →
// barzakh_validate of the whole corpus. No network, no privileges,
// deterministic output for a pinned barzakh release.
// ---------------------------------------------------------------------------

func TestE2E_BarzakhPurpleTeamLoop(t *testing.T) {
	requireBinary(t, "barzakh-adversary")
	requireBinary(t, "barzakh-scanner")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	corpusDir := filepath.Join(h.dir, "corpus")
	out := h.callTool(ctx, t, "barzakh_corpus", map[string]any{"output": corpusDir})
	if !strings.Contains(out, "UEFI Bootkit Corpus Generation") {
		t.Fatalf("barzakh_corpus output missing corpus header:\n%s", truncateForTest(out))
	}
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("corpus directory was not created: %v", err)
	}
	malicious := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "malicious_") {
			malicious++
		}
	}
	if malicious == 0 {
		t.Fatalf("corpus contains no malicious samples (%d entries)", len(entries))
	}

	sample := filepath.Join(corpusDir, "malicious_blacklotus_mok.bin")
	if _, err := os.Stat(sample); err != nil {
		// The pinned corpus layout documents blacklotus; fall back to any
		// malicious sample so a corpus reshuffle degrades, not breaks.
		pick := ""
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "malicious_") && strings.HasSuffix(e.Name(), ".bin") {
				pick = filepath.Join(corpusDir, e.Name())
				break
			}
		}
		if pick == "" {
			t.Fatalf("blacklotus sample missing and no fallback malicious sample found")
		}
		sample = pick
	}

	out = h.callTool(ctx, t, "barzakh_scan", map[string]any{"target": sample})
	// Exit code 1 (bootkit detected) must be a RESULT, not an error:
	// callTool already asserted !isError.
	if !strings.Contains(out, "BOOTKIT DETECTED") {
		t.Fatalf("barzakh_scan of a malicious sample did not surface the detection:\n%s", truncateForTest(out))
	}
	if !strings.Contains(out, "**Findings:**") {
		t.Fatalf("barzakh_scan did not render the per-severity findings summary:\n%s", truncateForTest(out))
	}
	var scanDoc struct {
		Status   string `json:"status"`
		Findings []struct {
			Severity string `json:"severity"`
			Title    string `json:"title"`
		} `json:"findings"`
		Summary struct {
			TotalFindings   int  `json:"total_findings"`
			BootkitDetected bool `json:"bootkit_detected"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &scanDoc); err != nil {
		t.Fatalf("barzakh_scan result JSON does not parse: %v", err)
	}
	if scanDoc.Status != "complete" {
		t.Errorf("scan status = %q, want complete", scanDoc.Status)
	}
	if !scanDoc.Summary.BootkitDetected || len(scanDoc.Findings) == 0 {
		t.Errorf("malicious sample reported no findings: %+v", scanDoc.Summary)
	}
	hasCritical := false
	for _, f := range scanDoc.Findings {
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("malicious blacklotus sample produced no critical findings: %+v", scanDoc.Findings)
	}

	out = h.callTool(ctx, t, "barzakh_validate", map[string]any{"corpus": corpusDir, "json": true})
	var validateDoc struct {
		Results []struct {
			PayloadName string `json:"payload_name"`
			Detected    bool   `json:"detected"`
		} `json:"results"`
		TotalPayloads int `json:"total_payloads"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &validateDoc); err != nil {
		t.Fatalf("barzakh_validate result JSON does not parse: %v\n%s", err, truncateForTest(out))
	}
	if validateDoc.TotalPayloads == 0 || len(validateDoc.Results) == 0 {
		t.Fatalf("barzakh_validate reported no corpus payloads: %+v", validateDoc)
	}
	detected := 0
	for _, r := range validateDoc.Results {
		if r.Detected {
			detected++
		}
	}
	if detected == 0 {
		t.Errorf("corpus validation detected none of %d malicious payloads", validateDoc.TotalPayloads)
	}

	// The real audit middleware must have recorded every tools/call.
	waitFor(t, "audit events for the barzakh tools", func() bool {
		called := h.auditToolCalls(t)
		return called["barzakh_corpus"] && called["barzakh_scan"] && called["barzakh_validate"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 2 (the gold test): a real multi-step CAMPAIGN whose steps execute
// real binaries through the full middleware chain and whose record rules
// persist the real scanner output into the target database.
//
// corpus step → scan step with a finding record rule over the scanner's
// ScanResult.findings array (the mapping verified by
// internal/app/recorder_golden_test.go against captured output). Asserts
// campaign success, per-step success, recorded counts, and the targetdb
// contents, plus the audit trail of the campaign-driven tool calls.
// ---------------------------------------------------------------------------

func TestE2E_CampaignBarzakhScanRecordsFindings(t *testing.T) {
	requireBinary(t, "barzakh-adversary")
	requireBinary(t, "barzakh-scanner")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	corpusDir := filepath.Join(h.dir, "corpus")
	sample := filepath.Join(corpusDir, "malicious_blacklotus_mok.bin")

	request := map[string]any{
		"id":   "e2e-barzakh-campaign",
		"name": "barzakh purple-team e2e",
		"steps": []any{
			map[string]any{
				"id":    "corpus",
				"tool":  "barzakh_corpus",
				"params": map[string]any{"output": corpusDir},
			},
			map[string]any{
				"id":    "scan",
				"tool":  "barzakh_scan",
				"params": map[string]any{"target": sample},
				"record": []any{map[string]any{
					"type": "finding",
					"path": "findings",
					"fields": map[string]string{
						"severity":    "severity",
						"title":       "title",
						"description": "description",
					},
				}},
				"mitre": []string{"T1542"},
			},
		},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshaling campaign request: %v", err)
	}
	result := h.campaignRun(ctx, t, string(raw))

	if !result.Success {
		t.Fatalf("campaign failed (status %q): %+v", result.Status, result)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("campaign executed %d steps, want 2", len(result.Steps))
	}
	for _, step := range result.Steps {
		if !step.Success {
			t.Errorf("campaign step %q (%s) failed:\n%s", step.ID, step.Tool, truncateForTest(step.Text))
		}
	}
	var scanStep *struct {
		Tool     string `json:"tool"`
		ID       string `json:"id,omitempty"`
		Success  bool   `json:"success"`
		Skipped  bool   `json:"skipped,omitempty"`
		Text     string `json:"text"`
		Recorded int    `json:"recorded,omitempty"`
	}
	for i := range result.Steps {
		if result.Steps[i].ID == "scan" {
			scanStep = &result.Steps[i]
		}
	}
	if scanStep == nil {
		t.Fatal("scan step missing from campaign result")
	}
	if scanStep.Recorded == 0 {
		t.Fatalf("scan step recorded no findings; record rule did not fire:\n%s", truncateForTest(scanStep.Text))
	}

	// The recorded findings must be in the real targetdb, mapped through
	// the real recorder: lowercase severities, tool attribution, campaign
	// MITRE enrichment, host fallback.
	findings := h.db.ListFindings()
	if len(findings) != scanStep.Recorded {
		t.Fatalf("targetdb has %d findings, scan step recorded %d", len(findings), scanStep.Recorded)
	}
	hasCritical := false
	for _, f := range findings {
		if f.Tool != "barzakh_scan" {
			t.Errorf("finding attributed to %q, want barzakh_scan", f.Tool)
		}
		if f.Host != "unknown" {
			t.Errorf("scan findings carry no host; expected \"unknown\", got %q", f.Host)
		}
		switch f.Severity {
		case "critical", "high", "medium", "low", "info":
		default:
			t.Errorf("finding severity %q not lowercased/known", f.Severity)
		}
		if f.Title == "" {
			t.Errorf("finding title missing: %+v", f)
		}
		if len(f.MITRE) == 0 || f.MITRE[0] != "T1542" {
			t.Errorf("finding MITRE enrichment wrong: %v", f.MITRE)
		}
		if f.Severity == "critical" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("no critical finding recorded from the malicious blacklotus sample")
	}

	// Campaign steps execute through srv.ExecuteTool, so the audit
	// middleware must have logged them too.
	waitFor(t, "audit events for the campaign steps", func() bool {
		called := h.auditToolCalls(t)
		return called["barzakh_corpus"] && called["barzakh_scan"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 3: nmap connect scan + service detection against a listener the
// test owns. SYN scans need root, so the port scan uses scan_type connect.
// ---------------------------------------------------------------------------

func TestE2E_NmapLocalhostScanAndServiceDetect(t *testing.T) {
	requireBinary(t, "nmap")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	port := serveLocalTCP(t)
	portSpec := fmt.Sprintf("%d", port)

	out := h.callTool(ctx, t, "nmap_port_scan", map[string]any{
		"target":    "127.0.0.1",
		"ports":     portSpec,
		"scan_type": "connect",
	})
	if !strings.Contains(out, "Open ports: 1") {
		t.Fatalf("connect scan did not report the test listener as open:\n%s", truncateForTest(out))
	}
	if !strings.Contains(out, fmt.Sprintf("| %d |", port)) {
		t.Fatalf("scan summary does not list port %d:\n%s", port, truncateForTest(out))
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("scan summary does not mention the scanned host:\n%s", truncateForTest(out))
	}

	out = h.callTool(ctx, t, "nmap_service_detect", map[string]any{
		"target": "127.0.0.1",
		"ports":  portSpec,
	})
	if !strings.Contains(out, "Open ports: 1") || !strings.Contains(out, fmt.Sprintf("| %d |", port)) {
		t.Fatalf("service detection did not report the test listener:\n%s", truncateForTest(out))
	}

	waitFor(t, "audit events for the nmap tools", func() bool {
		called := h.auditToolCalls(t)
		return called["nmap_port_scan"] && called["nmap_service_detect"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 4: nuclei against a local HTTP server with a test-authored
// template file. The template is file-based (no template directory, no
// downloads); the matcher is a static word on the response body the test
// handler always serves.
// ---------------------------------------------------------------------------

const nucleiTemplateYAML = `id: redhands-e2e-local-marker

info:
  name: RedHands E2E Local Marker
  author: redhands-e2e
  severity: info
  description: |
    Matches the fixed marker body served by the test-owned local HTTP
    server. Used only by the RedHands live e2e suite.

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "redhands-e2e-marker-7f3a"
`

func TestE2E_NucleiLocalTemplateScan(t *testing.T) {
	requireBinary(t, "nuclei")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	srv := serveLocalHTTP(t)

	templatePath := filepath.Join(h.dir, "redhands-e2e-local-marker.yaml")
	if err := os.WriteFile(templatePath, []byte(nucleiTemplateYAML), 0o600); err != nil {
		t.Fatalf("writing nuclei template: %v", err)
	}

	out := h.callTool(ctx, t, "nuclei_scan", map[string]any{
		"target":    srv.URL,
		"templates": templatePath,
	})
	if !strings.Contains(out, "Found 1 issue") {
		t.Fatalf("nuclei did not report the single expected finding:\n%s", truncateForTest(out))
	}
	if !strings.Contains(out, "redhands-e2e-local-marker") {
		t.Fatalf("nuclei output does not name the matched template:\n%s", truncateForTest(out))
	}
	if strings.Contains(out, "No vulnerabilities found") {
		t.Fatalf("nuclei reported no findings against the marker server:\n%s", truncateForTest(out))
	}

	waitFor(t, "audit event for nuclei_scan", func() bool {
		return h.auditToolCalls(t)["nuclei_scan"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 5: telecom_doctor — staticzero-defense --doctor --json is a
// read-only preflight. Privilege checks may fail (no root); the DoctorReport
// must render with a checks array, and the ebpf_object check must pass
// because the release binary embeds the eBPF object.
// ---------------------------------------------------------------------------

func TestE2E_TelecomDoctor(t *testing.T) {
	requireBinary(t, "staticzero-defense")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	out := h.callTool(ctx, t, "telecom_doctor", map[string]any{})
	if !strings.Contains(out, "StaticZero Defense Doctor") {
		t.Fatalf("doctor output missing its header:\n%s", truncateForTest(out))
	}
	var report struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
		Modules []struct {
			Module int    `json:"module"`
			Status string `json:"status"`
		} `json:"modules"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &report); err != nil {
		t.Fatalf("doctor report JSON does not parse: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("doctor report carries no checks array")
	}
	ebpfOK := false
	for _, c := range report.Checks {
		if c.Name == "ebpf_object" {
			if c.Status != "pass" {
				t.Errorf("ebpf_object check = %q (%s); the release binary must embed the eBPF object", c.Status, c.Detail)
			}
			ebpfOK = true
		}
	}
	if !ebpfOK {
		t.Errorf("doctor report has no ebpf_object check: %+v", report.Checks)
	}

	waitFor(t, "audit event for telecom_doctor", func() bool {
		return h.auditToolCalls(t)["telecom_doctor"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 6: telecom_firmware_analyze on a synthetic modem image. The image
// is assembled exactly like the documented fixture generator
// (testdata/telecom/README.md) except the random padding uses a fixed seed,
// so the finding set is deterministic: pattern hits for strcpy/sprintf,
// weak ciphers, debug interfaces, hardcoded credentials, and protocol
// handlers.
// ---------------------------------------------------------------------------

const firmwarePatternBlob = "strcpy sprintf A5/1 A5/0 password admin:admin root:root QXDM AT+DEBUG AT+UNLOCK AT+FACTORYRESET JTAG rrc_connection_setup nas_attach sip_invite gtp_create_session AT+CGMR"

func syntheticModemImage(t *testing.T) string {
	t.Helper()
	// Fixed seed: the padding must never contain the pattern strings.
	rng := rand.New(rand.NewSource(20261114))
	pad := func() []byte {
		buf := make([]byte, 16*1024)
		rng.Read(buf)
		return buf
	}
	path := filepath.Join(t.TempDir(), "synthetic-modem.bin")
	data := append(append(pad(), []byte(firmwarePatternBlob)...), pad()...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing synthetic firmware image: %v", err)
	}
	return path
}

func TestE2E_TelecomFirmwareAnalyze(t *testing.T) {
	requireBinary(t, "modem-firmware")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	image := syntheticModemImage(t)
	reportPath := filepath.Join(h.dir, "fw_analysis.json")

	out := h.callTool(ctx, t, "telecom_firmware_analyze", map[string]any{
		"target":  image,
		"chipset": "qualcomm",
		"report":  reportPath,
	})
	var report struct {
		FirmwarePath string `json:"firmware_path"`
		Chipset      string `json:"chipset"`
		Findings []struct {
			Severity string `json:"severity"`
			Category string `json:"category"`
			Title    string `json:"title"`
		} `json:"findings"`
		AttackSurfaces    []any `json:"attack_surfaces"`
		ProtocolHandlers []any `json:"protocol_handlers"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &report); err != nil {
		t.Fatalf("firmware analysis report does not parse: %v\n%s", err, truncateForTest(out))
	}
	if report.FirmwarePath != image || !strings.EqualFold(report.Chipset, "qualcomm") {
		t.Errorf("report attribution wrong: path=%q chipset=%q", report.FirmwarePath, report.Chipset)
	}
	if len(report.Findings) == 0 {
		t.Fatal("analyzer produced no findings for the pattern-laden synthetic image")
	}
	foundStrcpy := false
	for _, f := range report.Findings {
		if strings.Contains(f.Title, "strcpy") {
			foundStrcpy = true
		}
	}
	if !foundStrcpy {
		t.Errorf("no dangerous-function finding for strcpy: %+v", report.Findings)
	}
	if len(report.AttackSurfaces) == 0 || len(report.ProtocolHandlers) == 0 {
		t.Errorf("attack surfaces / protocol handlers missing: %d / %d", len(report.AttackSurfaces), len(report.ProtocolHandlers))
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("analyzer did not write the report file: %v", err)
	}

	waitFor(t, "audit event for telecom_firmware_analyze", func() bool {
		return h.auditToolCalls(t)["telecom_firmware_analyze"]
	})
}

// ---------------------------------------------------------------------------
// Scenario 7: kubedagger k8s discover against no cluster. Only asserts the
// call completes and returns a well-formed response without hanging — the
// empty-stdout/error-surfacing behavior is intentionally NOT asserted
// because the wrapper is being reworked to surface stderr. HOME is pointed
// at an empty temp dir so the client cannot pick up a developer's real
// kubeconfig, keeping the scenario fully offline.
// ---------------------------------------------------------------------------

func TestE2E_KubedaggerK8sDiscoverNoCluster(t *testing.T) {
	requireBinary(t, "kubedagger-client")
	// Never enumerate a real cluster: skip when running inside one.
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount"); err == nil {
		t.Skip("running inside a Kubernetes cluster; refusing to run the no-cluster scenario here")
	}
	h := newHarness(t)
	emptyHome := t.TempDir()
	t.Setenv("HOME", emptyHome)

	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	text, isErr := h.callToolRaw(ctx, t, "kubedagger_k8s_discover", map[string]any{
		"namespace": "redhands-e2e",
	})
	if isErr {
		// Expected on a clusterless machine: the k8s client cannot
		// initialize. An error RESULT (not a hang and not a JSON-RPC
		// protocol error) is the acceptable outcome.
		t.Logf("k8s discover failed without a cluster (acceptable): %s", truncateForTest(text))
	} else {
		t.Logf("k8s discover returned a result without a cluster: %s", truncateForTest(text))
	}
}
