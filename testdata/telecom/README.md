# Telecom (StaticZero) fixtures

Real stdout captures from the StaticZero telecom defense binaries, used by the
golden pipeline tests in `tools/telecom/doctor_golden_test.go` and
`pkg/workflow/golden_dataflow_test.go`.

## Provenance

All files in this directory are **real binary runs** (not hand-crafted) from
the StaticZero repository (`cargo build --release` produces `staticzero-defense`
and `modem-firmware` in `StaticZero/target/release`), executed offline on this
machine. The captures were taken without root, which is itself part of the
fixture: `--doctor` exits non-zero when the preflight fails but still prints
the full DoctorReport JSON on stdout (that is the failure shape the
`telecom_doctor` wrapper must render, not an error).

```bash
# doctor-report.json  (exit 1: privileges check fails without CAP_BPF — real
# failure shape; other checks pass)
staticzero-defense --doctor --json

# doctor-report-all-modules.json  (same preflight, --all module groups)
staticzero-defense --doctor --json --all

# firmware-analysis.json + firmware-analyze-stdout.txt
# (synthetic image assembled offline; the analyzer accepts arbitrary binaries)
head -c 16k  /dev/urandom                       >  /tmp/pad1.bin
printf 'strcpy sprintf A5/1 A5/0 password admin:admin root:root QXDM AT+DEBUG AT+UNLOCK AT+FACTORYRESET JTAG rrc_connection_setup nas_attach sip_invite gtp_create_session AT+CGMR' > /tmp/patterns.bin
head -c 16k  /dev/urandom                      >> /tmp/patterns.bin   # trailing pad
cat /tmp/pad1.bin /tmp/patterns.bin             >  /tmp/synthetic-modem.bin
modem-firmware analyze --target /tmp/synthetic-modem.bin --chipset qualcomm --report fw_analysis.json

# firmware-nv-items.json
modem-firmware nv-dump --image /tmp/synthetic-modem.bin --output nv_items.json
```

## Shape notes (verified against these real captures)

- `staticzero-defense --doctor --json` prints
  `{checks: [{name, status, detail}, ...], modules: [{module, program,
  description, status, detail}, ...]}` on stdout and exits 1 when any check
  fails. `status` values seen: `pass`, `fail`, `warning`; module status also
  `unsupported`.
- `modem-firmware analyze` writes the report to the `--report` path (default
  `./fw_analysis.json`) and logs progress lines to stdout. The report is
  `{firmware_path, chipset, findings: [{severity, category, title,
  description, offset, size, cve}, ...], attack_surfaces, protocol_handlers,
  nv_items_of_interest}`. Severity values are capitalized
  (`High`/`Medium`/`Low`/`Info`); the `telecom_firmware_analyze` wrapper
  lowercases them when embedding the report, so the fixture keeps the raw
  capitalized capture while wrapper consumers see lowercase.
- `modem-firmware nv-dump` writes a JSON array of NV items
  (`[{id, name, value, description, security_relevant}, ...]`).
