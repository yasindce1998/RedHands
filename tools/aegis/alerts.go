package aegis

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	// maxAlertFileSize caps NDJSON alert files accepted by the read tools so
	// a runaway daemon log cannot exhaust memory.
	maxAlertFileSize = 64 << 20 // 64 MiB
	// alertDisplayLimit caps how many matching alerts are rendered in a
	// single aegis_alerts_parse result.
	alertDisplayLimit = 200
)

// AlertRecord mirrors the Aegis-Shadow defense::AlertRecord JSON schema
// (defense/src/lib.rs). The defense daemon writes one such object per line
// (NDJSON) via `-o <file>` or `--json-stdout`.
type AlertRecord struct {
	Timestamp       uint64   `json:"timestamp"`
	AlertType       string   `json:"alert_type"`
	Severity        string   `json:"severity"`
	PID             uint32   `json:"pid"`
	Context         uint64   `json:"context"`
	Details         string   `json:"details"`
	AnomalyScore    float64  `json:"anomaly_score"`
	CorrelatedTypes []string `json:"correlated_types"`
	IsAttackChain   bool     `json:"is_attack_chain"`
}

// alertFilter selects a subset of parsed alerts. An empty minSeverity means
// no severity floor.
type alertFilter struct {
	minSeverity string
	onlyChains  bool
	minAnomaly  float64
}

func (f alertFilter) matches(a AlertRecord) bool {
	if f.minSeverity != "" && severityRank(a.Severity) < severityRank(f.minSeverity) {
		return false
	}
	if f.onlyChains && !a.IsAttackChain {
		return false
	}
	if a.AnomalyScore < f.minAnomaly {
		return false
	}
	return true
}

func filterAlerts(alerts []AlertRecord, f alertFilter) []AlertRecord {
	var out []AlertRecord
	for _, a := range alerts {
		if f.matches(a) {
			out = append(out, a)
		}
	}
	return out
}

// parseAlertsFile reads an NDJSON alert file produced by the defense daemon
// and returns the parsed records plus the count of malformed lines skipped.
func parseAlertsFile(path string) ([]AlertRecord, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read alert file: %v", err)
	}
	var alerts []AlertRecord
	malformed := 0
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var a AlertRecord
		if err := json.Unmarshal([]byte(trimmed), &a); err != nil {
			malformed++
			continue
		}
		alerts = append(alerts, a)
	}
	return alerts, malformed, nil
}

// alertsReport carries everything renderAlertsReport needs to display a
// filtered view of an alert file.
type alertsReport struct {
	file      string
	total     int
	malformed int
	matching  []AlertRecord
	filters   []string
	scopeNote string
	limit     int
}

func renderAlertsReport(r alertsReport) string {
	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Alert Analysis\n\n")
	fmt.Fprintf(&sb, "- **File:** `%s`\n", r.file)
	fmt.Fprintf(&sb, "- **Parsed alerts:** %d (skipped malformed lines: %d)\n", r.total, r.malformed)
	fmt.Fprintf(&sb, "- **Matching alerts:** %d\n", len(r.matching))
	if len(r.filters) > 0 {
		fmt.Fprintf(&sb, "- **Filters:** %s\n", strings.Join(r.filters, "; "))
	}
	if r.scopeNote != "" {
		fmt.Fprintf(&sb, "- **Scope:** %s\n", r.scopeNote)
	}
	chains := 0
	chainPIDs := map[uint32]bool{}
	for _, a := range r.matching {
		if a.IsAttackChain {
			chains++
			chainPIDs[a.PID] = true
		}
	}
	fmt.Fprintf(&sb, "- **Attack-chain alerts:** %d\n", chains)
	sb.WriteString("\n")

	if len(r.matching) == 0 {
		sb.WriteString("No matching alerts.\n")
		return sb.String()
	}

	sb.WriteString("### Severity breakdown (matching)\n\n")
	sb.WriteString(renderSeverityBreakdown(r.matching))

	limit := r.limit
	if limit <= 0 || limit > len(r.matching) {
		limit = len(r.matching)
	}
	shown := r.matching[:limit]

	sb.WriteString("\n### Matching alerts\n\n")
	sb.WriteString("| Timestamp (ns) | Severity | Alert type | PID | Anomaly score | Attack chain |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, a := range shown {
		fmt.Fprintf(&sb, "| %d | %s | %s | %d | %.2f | %v |\n",
			a.Timestamp, a.Severity, a.AlertType, a.PID, a.AnomalyScore, a.IsAttackChain)
	}
	if limit < len(r.matching) {
		fmt.Fprintf(&sb, "\nShowing first %d of %d matching alerts.\n", limit, len(r.matching))
	}

	if b, err := json.MarshalIndent(shown, "", "  "); err == nil {
		sb.WriteString("\nFull records (JSON):\n\n```json\n")
		sb.Write(b)
		sb.WriteString("\n```\n")
	}
	return sb.String()
}

func renderSeverityBreakdown(matching []AlertRecord) string {
	counts := map[string]int{}
	for _, a := range matching {
		counts[a.Severity]++
	}
	ordered := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	seen := map[string]bool{}
	var sb strings.Builder
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range ordered {
		seen[sev] = true
		if counts[sev] > 0 {
			fmt.Fprintf(&sb, "| %s | %d |\n", sev, counts[sev])
		}
	}
	var extra []string
	for sev := range counts {
		if !seen[sev] {
			extra = append(extra, sev)
		}
	}
	sort.Strings(extra)
	for _, sev := range extra {
		fmt.Fprintf(&sb, "| %s | %d |\n", sev, counts[sev])
	}
	return sb.String()
}
