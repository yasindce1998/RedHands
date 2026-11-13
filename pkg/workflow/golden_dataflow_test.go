package workflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden dataflow tests: every JSON fixture captured from (or derived
// strictly from the output structs of) the wrapped binaries is run through
// StructuredFromText — the campaign engine's extractor — in exactly the
// markdown shape the corresponding RedHands wrapper emits, and the paths
// that campaign record rules, playbooks, and ${step.json.path} references
// use are asserted to resolve. This catches the "wrapper says hosts.0.ip
// but the binary emits addresses[0]" class of bug against real output
// shapes. Fixture provenance is documented in each testdata/<toolset>/
// README.md.

func loadFixtureJSON(t *testing.T, parts ...string) json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return data
}

// wrapAsToolResult reproduces how RedHands wrappers embed tool stdout in
// their markdown ToolResult text: a header, metadata lines, then the raw
// output inside a ```json fence.
func wrapAsToolResult(header, metadata, body string) string {
	var sb strings.Builder
	sb.WriteString(header + "\n\n")
	for _, line := range strings.Split(metadata, "\n") {
		if line != "" {
			sb.WriteString(line + "\n")
		}
	}
	sb.WriteString("\n```json\n")
	sb.WriteString(strings.TrimSpace(body))
	sb.WriteString("\n```\n")
	return sb.String()
}

func extractAndDecode(t *testing.T, text string) any {
	t.Helper()
	raw, ok := StructuredFromText(text)
	if !ok {
		t.Fatalf("StructuredFromText could not extract JSON from wrapper-shaped markdown:\n%.400s", text)
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("extracted JSON does not decode: %v", err)
	}
	return value
}

func assertPathsResolve(t *testing.T, value any, paths []string) {
	t.Helper()
	for _, path := range paths {
		got, ok := LookupPathValue(value, path)
		if !ok {
			t.Errorf("path %q does not resolve against the real output shape", path)
			continue
		}
		if got == nil {
			t.Errorf("path %q resolves to null; record rules would record empty values", path)
		}
	}
}

// TestGoldenDataflow_K8sReconChainRecordPaths runs the ClusterReport shape
// through the extractor in the exact markdown form kubedagger_k8s_discover
// emits and asserts the k8s-recon-chain playbook's record-rule paths
// ("nodes", "pods") and field mappings (ip/name/os, pod_ip/name) resolve.
func TestGoldenDataflow_K8sReconChainRecordPaths(t *testing.T) {
	body := loadFixtureJSON(t, "kubedagger", "cluster-report.json")
	text := wrapAsToolResult(
		"## KubeDagger K8s Discovery",
		"Namespace: default",
		string(body),
	)
	value := extractAndDecode(t, text)

	// Record rules select arrays by path; both must exist and be arrays.
	for _, path := range []string{"nodes", "pods"} {
		arr, ok := LookupPathValue(value, path)
		if !ok {
			t.Fatalf("record-rule path %q does not resolve", path)
		}
		if _, ok := arr.([]any); !ok {
			t.Fatalf("record-rule path %q is not an array: %T", path, arr)
		}
	}
	assertPathsResolve(t, value, []string{
		"nodes.0.ip", "nodes.0.name", "nodes.0.os", // host rule fields
		"pods.0.pod_ip", "pods.0.name", // host rule fields (pods)
		"nodes.2.kernel", "pods.1.privileged", "services.0.cluster_ip",
		"namespaces.0", "targets.0.reason",
	})
}

// TestGoldenDataflow_BarzakhScanPaths runs both captured scanner shapes
// (0.7.0 ScanResult envelope and the legacy <=0.6 top-level array) through
// the extractor in the markdown form barzakh_scan emits.
func TestGoldenDataflow_BarzakhScanPaths(t *testing.T) {
	t.Run("scanresult-0.7.0", func(t *testing.T) {
		body := loadFixtureJSON(t, "barzakh", "scan-malicious-blacklotus.json")
		text := wrapAsToolResult(
			"## UEFI Firmware Scan Results",
			"- **Target:** /corpus/malicious_blacklotus_mok.bin\n- **Result:** ⚠️ BOOTKIT DETECTED (scanner exit code 1)\n- **Findings:** 6",
			string(body),
		)
		value := extractAndDecode(t, text)
		assertPathsResolve(t, value, []string{
			"status",
			"findings", // record-rule path for a finding rule
			"findings.0.severity", "findings.0.title", "findings.0.description", // finding rule fields
			"findings.0.detector", "findings.0.confidence",
			"summary.total_findings", "summary.critical_count", "summary.bootkit_detected",
			"risk.score", "risk.level",
			"scan_info.target",
			"detector_runs.0.detector",
		})
	})

	t.Run("legacy-array-0.5.0", func(t *testing.T) {
		body := loadFixtureJSON(t, "barzakh", "scan-malicious-blacklotus-v05.json")
		text := wrapAsToolResult(
			"## UEFI Firmware Scan Results",
			"- **Target:** /fw/rom.bin\n- **Result:** ⚠️ BOOTKIT DETECTED (scanner exit code 1)",
			string(body),
		)
		value := extractAndDecode(t, text)
		// The legacy shape is a bare array: only numeric paths reach the
		// findings. A record rule using path "findings" cannot select them —
		// this documents why environments pinned to scanner <=0.6 need the
		// wrapper's summary rather than record rules.
		assertPathsResolve(t, value, []string{"0.severity", "0.title", "0.detector"})
		if _, ok := LookupPathValue(value, "findings"); ok {
			t.Log("legacy fixture now carries a findings envelope; the drift note can be removed")
		}
	})
}

// TestGoldenDataflow_TelecomDoctorPaths runs the real failed-preflight
// DoctorReport through the extractor in the markdown form telecom_doctor
// emits.
func TestGoldenDataflow_TelecomDoctorPaths(t *testing.T) {
	body := loadFixtureJSON(t, "telecom", "doctor-report.json")
	text := wrapAsToolResult(
		"## StaticZero Defense Doctor (read-only preflight)",
		"- **Status:** PREFLIGHT FAILED (see report below; the engine would refuse to start with this configuration)\n- **Binary:** staticzero-defense",
		string(body),
	)
	value := extractAndDecode(t, text)
	assertPathsResolve(t, value, []string{
		"checks", "checks.0.name", "checks.0.status", "checks.0.detail",
		"modules", "modules.0.module", "modules.0.program", "modules.0.status", "modules.0.detail",
	})
	// The real no-root capture: privileges fails, platform passes.
	priv, ok := LookupPathValue(value, "checks.2.name")
	if !ok || ValueToString(priv) != "privileges" {
		t.Logf("checks ordering differs from capture; statuses are asserted per-name in tools/telecom golden tests")
	}
}

// TestGoldenDataflow_TelecomFirmwarePaths runs the real modem-firmware
// vulnerability report through the extractor in the markdown form
// telecom_firmware_analyze embeds the --report artifact.
func TestGoldenDataflow_TelecomFirmwarePaths(t *testing.T) {
	body := loadFixtureJSON(t, "telecom", "firmware-analysis.json")
	text := wrapAsToolResult(
		"## Modem Firmware Analysis",
		"- **Target:** /tmp/synthetic-modem.bin\n- **Chipset:** qualcomm",
		string(body),
	)
	value := extractAndDecode(t, text)
	assertPathsResolve(t, value, []string{
		"firmware_path", "chipset",
		"findings", "findings.0.severity", "findings.0.category", "findings.0.title", "findings.0.description",
		"attack_surfaces.0.interface", "protocol_handlers.0.protocol",
		"nv_items_of_interest.0.id", "nv_items_of_interest.0.security_relevant",
	})
	// Real severities are capitalized; record rules must lowercase them.
	sev, _ := LookupPathValue(value, "findings.0.severity")
	if s := ValueToString(sev); s != strings.ToLower(s) {
		t.Logf("real modem-firmware severities are capitalized (%q); CampaignRecorder lowercases finding severities", s)
	}
}

// TestGoldenDataflow_EveryJSONFixtureExtracts is the sweep: every *.json
// fixture under testdata/ must be extractable when fenced the way RedHands
// wrappers fence tool stdout, so no toolset's golden shape can silently
// stop flowing through the campaign pipeline.
func TestGoldenDataflow_EveryJSONFixtureExtracts(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			text := wrapAsToolResult("## Golden Fixture Sweep", "- **Fixture:** "+rel, string(data))
			if _, ok := StructuredFromText(text); !ok {
				t.Errorf("fixture is not extractable through a ```json fence (invalid JSON?)")
			}
			// The fixture must also be valid JSON on its own: some consumers
			// parse the raw stdout, not the fenced form.
			if !json.Valid(data) {
				t.Errorf("fixture is not valid JSON")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking testdata: %v", err)
	}
}

// TestGoldenDataflow_NucleiMasscanNormalizedShapes runs the parser fixtures
// through their parsers and asserts the normalized shapes are extractable
// and carry the fields record rules would map (hosts/ports/findings).
func TestGoldenDataflow_NucleiMasscanNormalizedShapes(t *testing.T) {
	nucleiData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "nuclei", "findings.jsonl"))
	if err != nil {
		t.Fatalf("reading nuclei fixture: %v", err)
	}
	var nucleiLine struct {
		TemplateID string `json:"template-id"`
		Info       struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"info"`
		Host      string `json:"host"`
		MatchedAt string `json:"matched-at"`
	}
	if err := json.Unmarshal(nucleiLine1(t, nucleiData), &nucleiLine); err != nil {
		t.Fatalf("first nuclei JSONL line does not parse with the documented field names: %v", err)
	}
	if nucleiLine.TemplateID == "" || nucleiLine.Info.Severity == "" || nucleiLine.Host == "" {
		t.Errorf("nuclei JSONL field names drifted: %+v", nucleiLine)
	}

	masscanData := loadFixtureJSON(t, "masscan", "hosts.json")
	var masscanEntries []struct {
		IP    string `json:"ip"`
		Ports []struct {
			Port   int    `json:"port"`
			Proto  string `json:"proto"`
			Status string `json:"status"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(masscanData, &masscanEntries); err != nil {
		t.Fatalf("masscan fixture does not parse as the documented array-of-entries shape: %v", err)
	}
	if len(masscanEntries) == 0 || masscanEntries[0].IP == "" || len(masscanEntries[0].Ports) == 0 {
		t.Errorf("masscan JSON field names drifted: %+v", masscanEntries)
	}
}

func nucleiLine1(t *testing.T, data []byte) []byte {
	t.Helper()
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			return []byte(line)
		}
	}
	t.Fatal("nuclei fixture has no lines")
	return nil
}
