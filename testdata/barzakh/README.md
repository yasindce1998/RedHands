# Barzakh fixtures

Real stdout captures from the Barzakh scanner/adversary binaries, used by the
golden pipeline tests in `tools/barzakh/scan_golden_test.go`,
`pkg/workflow/golden_dataflow_test.go`, and `internal/app/recorder_golden_test.go`.

## Provenance

All files in this directory are **real binary runs** (not hand-crafted),
executed offline on this machine. Rebuild/run commands (from the Barzakh
repository):

```bash
# binaries (barzakh-scanner / barzakh-adversary 0.7.0, debug or release)
cd Barzakh/src/barzakh-scanner-rs && cargo build

# corpus used as scan input
barzakh-adversary corpus --output <corpus-dir>

# scan-malicious-blacklotus.json  (barzakh-scanner 0.7.0; exits 1 = bootkit detected)
barzakh-scanner scan --target <corpus-dir>/malicious_blacklotus_mok.bin --json

# scan-clean-blacklotus.json      (0.7.0; exit 0, findings array still non-empty)
barzakh-scanner scan --target <corpus-dir>/clean_blacklotus_mok.bin --json

# scan-malicious-blacklotus-v05.json  (barzakh-scanner 0.5.0 legacy shape;
# see "Output shape history" below)
barzakh-scanner-0.5.0 scan --target <corpus-dir>/malicious_blacklotus_mok.bin --json

# adversary-validate.json
barzakh-adversary validate --corpus <corpus-dir> --json

# scenario-list.txt
barzakh-adversary scenario list

# scenario-run-blacklotus-chain.json  (exit 0 = chain fully detected;
# exit 1 = chain not fully detected, still valid JSON on stdout)
barzakh-adversary scenario run --name blacklotus-chain --json

# detectors-list.txt
barzakh-scanner detectors list

# scanner-info.txt
barzakh-scanner info
```

## Output shape history (verified against these real captures)

- barzakh-scanner **0.7.0** `scan --json` emits a `ScanResult` **object**:
  `{status, detector_runs: [{detector, status, finding_count, error,
  duration_seconds}, ...], errors, input_sha256, event_log_sha256,
  summary: {total_findings, critical_count, high_count, medium_count,
  low_count, info_count, bootkit_detected}, findings: [{detector, severity,
  title, description, confidence, details, recommendation, evidence_kind},
  ...], scan_info: {target, start_time, end_time, duration_seconds}, risk:
  {score, level, vector, weighted_sum, mean_confidence, detector_count}}`.
  Exit code 1 means "bootkit detected"; exit code 2 means "scan incomplete".
  (Per CHANGELOG: "Compatibility: `scan --json` emits a ScanResult object
  rather than an array; findings are at `.findings`.")
- barzakh-scanner **0.5.0** (legacy, `scan-malicious-blacklotus-v05.json`)
  emitted a **top-level JSON array** of finding objects with no envelope —
  there was no `{"findings": [...]}` wrapper and no summary/risk block.
  The `barzakh_scan` severity summary historically did not render against
  this shape; the wrapper now accepts both.
- `barzakh-adversary validate --corpus --json` emits an object:
  `{results: [{payload_name, detected, expected_findings, matched_findings,
  extra_findings}, ...], total_payloads, detected_count, missed_count,
  true_positive_rate, false_positives, true_negatives, false_positive_rate}`.
- `barzakh-adversary scenario run --name <chain> --json` emits
  `{name, stages: [{label, payload, generated_file, detected_by, risk_score,
  detected}, ...], chain_validated, chain_rendering}`.
- `scenario list` and `detectors list` emit human-readable tables (not JSON).

