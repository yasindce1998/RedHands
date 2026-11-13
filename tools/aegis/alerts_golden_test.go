package aegis

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/workflow"
)

// Golden tests for aegis_alerts_parse / aegis_alerts_tail against NDJSON
// fixtures in testdata/aegis/. The fixtures are schema-derived (hand-crafted
// strictly against the Aegis-Shadow defense::AlertRecord serde schema — see
// the README there for why live daemon output cannot be captured without
// root + a compiled eBPF object). These tests exercise the real parsing and
// filtering path: severity floors, attack-chain selection, anomaly-score
// floors, malformed-line counting, and tail windows.

func goldenAlertPath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", "aegis", name))
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	return path
}

func mustRunAlertsParse(t *testing.T, params string) string {
	t.Helper()
	tool := NewAlertsParse()
	result, err := tool.Execute(context.Background(), []byte(params))
	if err != nil {
		t.Fatalf("aegis_alerts_parse returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("aegis_alerts_parse failed: %s", result.Content[0].Text)
	}
	return result.Content[0].Text
}

func mustRunAlertsTail(t *testing.T, params string) string {
	t.Helper()
	tool := NewAlertsTail()
	result, err := tool.Execute(context.Background(), []byte(params))
	if err != nil {
		t.Fatalf("aegis_alerts_tail returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("aegis_alerts_tail failed: %s", result.Content[0].Text)
	}
	return result.Content[0].Text
}

// TestAlertsParseGolden_NoFiltersCountsEverySchemaField: the fixture models
// two PIDs — 1337 escalating into a flagged attack chain (4 chain alerts)
// and 8080 with correlated but sub-threshold activity — plus isolated alerts
// for 4242 and 5555. Totals: 12 records, 4 attack-chain, severity mix
// 2 LOW / 5 MEDIUM / 3 HIGH / 2 CRITICAL.
func TestAlertsParseGolden_NoFiltersCountsEverySchemaField(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`"}`)

	for _, want := range []string{
		"Parsed alerts:** 12 (skipped malformed lines: 0)",
		"Matching alerts:** 12",
		"Attack-chain alerts:** 4",
		"| CRITICAL | 2 |",
		"| HIGH | 3 |",
		"| MEDIUM | 5 |",
		"| LOW | 2 |",
		"Full records (JSON)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}
	// The rendered matching-alerts table and the JSON records block must
	// carry the schema fields the defense daemon actually emits.
	for _, want := range []string{
		"| BPF Map C2 Signature", // alert_type label from classify_alert_type
		"1337",                   // pid
		"10.60",                  // anomaly_score formatting
		"is_attack_chain",
		"correlated_types",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing schema field marker %q:\n%s", want, text)
		}
	}
}

// TestAlertsParseGolden_SeverityFloor: severity >= HIGH selects the 5 alerts
// at HIGH or CRITICAL (Ghost Map, Memory-Backed Execution, Hidden Process,
// BPF Map C2 Signature, Honeypot Map Accessed).
func TestAlertsParseGolden_SeverityFloor(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "severity": "HIGH"}`)
	for _, want := range []string{
		"Matching alerts:** 5",
		"Filters:** severity >= HIGH",
		"Attack-chain alerts:** 3", // chain alerts at HIGH+: Memory-Backed, Hidden Process, BPF Map C2
	} {
		if !strings.Contains(text, want) {
			t.Errorf("severity-floor report missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "| Syscall Latency Anomaly") {
		t.Errorf("LOW/MEDIUM alerts leaked through the HIGH floor:\n%s", text)
	}
}

// TestAlertsParseGolden_AttackChainsOnly: only_attack_chains selects the 4
// chain alerts, all belonging to pid 1337.
func TestAlertsParseGolden_AttackChainsOnly(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "only_attack_chains": true}`)
	for _, want := range []string{
		"Matching alerts:** 4",
		"Attack-chain alerts:** 4",
		"Memory-Backed Execution",
		"Process Contained",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("attack-chain report missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "| Honeypot Map Accessed") {
		t.Errorf("non-chain CRITICAL honeypot alert leaked into chains-only view:\n%s", text)
	}
}

// TestAlertsParseGolden_AnomalyFloor: min_anomaly_score 10.0 selects the two
// anomaly-escalated CRITICAL alerts (10.6 BPF C2, 10.2 honeypot) — pinning
// the ANOMALY_CRITICAL = 10.0 escalation threshold semantics.
func TestAlertsParseGolden_AnomalyFloor(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "min_anomaly_score": 10.0}`)
	for _, want := range []string{
		"Matching alerts:** 2",
		"anomaly_score >= 10.00",
		"BPF Map C2 Signature",
		"Honeypot Map Accessed",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("anomaly-floor report missing %q:\n%s", want, text)
		}
	}
}

// TestAlertsParseGolden_CombinedFilters: CRITICAL + chains only selects just
// the BPF Map C2 Signature alert.
func TestAlertsParseGolden_CombinedFilters(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "severity": "CRITICAL", "only_attack_chains": true}`)
	if !strings.Contains(text, "Matching alerts:** 1") {
		t.Errorf("combined filters should match exactly 1 alert:\n%s", text)
	}
	if !strings.Contains(text, "BPF Map C2 Signature") {
		t.Errorf("combined filters should keep the chain CRITICAL alert:\n%s", text)
	}
}

// TestAlertsParseGolden_TornWriteCountsMalformed: the torn-write fixture
// simulates a daemon killed mid-write. Of its 6 non-empty lines, 2 are
// malformed (a truncated JSON line and a non-JSON line). A syntactically
// valid but sparse object ({"severity":"HIGH"}) still parses — Go has no
// required-field validation — so parsed=4, malformed=2. This pins the
// parser's real robustness contract.
func TestAlertsParseGolden_TornWriteCountsMalformed(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts-torn-write.ndjson")+`"}`)
	for _, want := range []string{
		"Parsed alerts:** 4 (skipped malformed lines: 2)",
		"Matching alerts:** 4",
		"Attack-chain alerts:** 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("torn-write report missing %q:\n%s", want, text)
		}
	}
	// The sparse object contributes a HIGH-severity zero-pid record alongside
	// the two real HIGH alerts (Ghost Map, Memory-Backed Execution).
	if !strings.Contains(text, "| HIGH | 3 |") {
		t.Errorf("sparse-object severity accounting changed:\n%s", text)
	}
}

// TestAlertsTailGolden_WindowAndSeverityFloor: tail with severity MEDIUM
// drops the 2 LOW alerts (10 severity-matching) and returns the last 2 with
// a scope note.
func TestAlertsTailGolden_WindowAndSeverityFloor(t *testing.T) {
	text := mustRunAlertsTail(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "count": 2, "severity": "MEDIUM"}`)
	for _, want := range []string{
		"Parsed alerts:** 12 (skipped malformed lines: 0)",
		"Matching alerts:** 2",
		"Scope:** last 2 of 10 severity-matching alerts",
		"Rapid BPF Detach",
		"Suspicious Hook Detected",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("tail report missing %q:\n%s", want, text)
		}
	}
}

// TestAlertsTailGolden_DefaultCountShowsAll: with no count, the default
// window (20) covers all 12 fixture alerts, so no scope note is emitted.
func TestAlertsTailGolden_DefaultCountShowsAll(t *testing.T) {
	text := mustRunAlertsTail(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`"}`)
	if !strings.Contains(text, "Matching alerts:** 12") {
		t.Errorf("default tail window should show all 12 alerts:\n%s", text)
	}
	if strings.Contains(text, "Scope:") {
		t.Errorf("no scope note expected when the window covers everything:\n%s", text)
	}
}

// TestAlertsParseGolden_RecordsBlockIsCampaignExtractable verifies the JSON
// records block embedded in the parse result is itself extractable by the
// campaign engine — a playbook step over aegis_alerts_parse can reference
// the alert fields.
func TestAlertsParseGolden_RecordsBlockIsCampaignExtractable(t *testing.T) {
	text := mustRunAlertsParse(t, `{"file": "`+goldenAlertPath(t, "alerts.ndjson")+`", "severity": "CRITICAL"}`)

	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatal("campaign extractor could not pull the alerts JSON block out of the parse result markdown")
	}
	var records []AlertRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatalf("extracted block is not the alert records array: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected the 2 CRITICAL records in the JSON block, got %d", len(records))
	}
	for _, r := range records {
		if r.Severity != "CRITICAL" || r.Timestamp == 0 || r.AlertType == "" {
			t.Errorf("record lost schema fields in rendering: %+v", r)
		}
	}
}
