# Aegis-Shadow alert fixtures

NDJSON alert files consumed by `aegis_alerts_parse` / `aegis_alerts_tail`
(golden tests in `tools/aegis/alerts_golden_test.go`).

## Provenance — schema-derived (documented)

The Aegis-Shadow defense daemon needs root + `CAP_BPF`/`CAP_PERFMON` and a
compiled eBPF object to emit live alerts, so these lines were **hand-crafted
strictly against the `AlertRecord` serde schema** in
`Aegis-Shadow/defense/src/lib.rs`:

```rust
pub struct AlertRecord {
    pub timestamp: u64,                 // nanoseconds since epoch
    pub alert_type: String,             // classify_alert_type() labels
    pub severity: String,               // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    pub pid: u32,
    pub context: u64,
    pub details: String,                // format_alert_details() output
    pub anomaly_score: f64,             // serde default; ANOMALY_CRITICAL = 10.0
    pub correlated_types: Vec<String>,  // serde default
    pub is_attack_chain: bool,          // >= 3 distinct alert types for the pid
}
```

The daemon serializes one compact JSON object per line (`writeln!` of
`serde_json::to_string`), which is exactly the NDJSON shape here. Field names,
severity labels, alert-type labels (`classify_alert_type`), the attack-chain
rule (`ATTACK_CHAIN_THRESHOLD = 3` distinct types), and the anomaly escalation
rule (`anomaly_score >= 10.0` forces `CRITICAL`) all come from that source.
`alerts.ndjson` models two PIDs: 1337 escalating into a flagged attack chain,
and 8080 with correlated but sub-threshold activity.

`alerts-torn-write.ndjson` simulates a daemon killed mid-write: it contains a
truncated line, a bare JSON fragment, and a non-JSON line. It exists to pin
the parser's malformed-line counting; real daemons killed by signal produce
exactly this shape.
