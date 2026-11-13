# nuclei fixtures

`findings.jsonl` is consumed by the golden parser tests in
`pkg/parser/golden_test.go`.

## Provenance — schema-derived (documented)

nuclei is not installed on this machine and needs live targets, so this file
was hand-crafted to match nuclei' documented JSONLines output mode
(`nuclei -j` / `-jsonl`, one compact JSON object per finding) and the field
selection of `pkg/parser/nuclei_json.go`. Each line carries the keys nuclei
emits and the parser reads — `template-id`, `info{name,severity}`, `host`,
`matched-at`, `type`, `ip`, `extracted-results` — plus realistic extra keys
nuclei also emits (`template-path`, `timestamp`, `curl-command`,
`matcher-status`, `info.tags`, `info.author`, `info.reference`) so the parser
must skip unknown fields exactly as it does against real output. The lines
include `http`, `dns`, and `file` template types and an `info`-severity only
finding. Reproduce real output with:

```bash
nuclei -u http://127.0.0.1:8080 -j -silent
```
