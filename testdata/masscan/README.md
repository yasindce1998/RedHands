# masscan fixtures

`hosts.json` is consumed by the golden parser tests in
`pkg/parser/golden_test.go`.

## Provenance — schema-derived (documented)

masscan is not installed on this machine and needs raw-socket privileges, so
this file was hand-crafted to match masscan's JSON output mode (`-oJ`) and the
field selection of `pkg/parser/masscan_json.go`: a top-level JSON array of
`{ip, timestamp, ports: [{port, proto, status, reason, ttl}]}` entries. It
deliberately contains two entries for the same IP (`192.0.2.50`) to pin the
parser's host-merging behavior, mixed `tcp`/`udp` protocols, and multiple
ports per host. Reproduce real output with:

```bash
masscan 192.0.2.0/24 -p 22,53,443,3389,8080,8443 -oJ -
```
