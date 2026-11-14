<p align="center">
  <img src="docs/logo.png" alt="RedHands Logo" width="250" height="250"/>
</p>

<h1 align="center">RedHands</h1>

<p align="center">
  <strong>MCP server for authorized security assessments</strong>
</p>

<p align="center">
  <a href="https://github.com/yasindce1998/redhands/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/yasindce1998/redhands/ci.yml?style=flat-square&logo=github&logoColor=white&label=CI&color=00c853" alt="CI"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26.11+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26.11+"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Compatible-ff2d2d?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjEwIiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiLz48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIzIi8+PC9zdmc+" alt="MCP Compatible"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-bf5fff?style=flat-square" alt="License: MIT"></a>
  <a href="https://github.com/yasindce1998/redhands"><img src="https://img.shields.io/badge/Tools-277-00fff2?style=flat-square" alt="277 Tools"></a>
</p>

<p align="center">
  Built in Go with zero external dependencies. Multi-transport (stdio/SSE/WebSocket), tool chaining,<br/>
  structured parsing, report generation, plugin system, rate limiting, caching, and audit logging.
</p>

```
go install github.com/yasindce1998/redhands/cmd/redhands@latest
```

## Quick Start

### One-Line Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/yasindce1998/redhands/main/scripts/install.sh | bash
```

This verifies a release archive against its published `SHA256SUMS` and prints MCP
configuration instructions. Older releases without checksums must be built from source.
To install security tools, use a reviewed checkout containing the dependency lock:

```bash
git clone https://github.com/yasindce1998/redhands.git && cd redhands
sudo ./scripts/install-tools.sh --profile web
```

### Install from Source

```bash
git clone https://github.com/yasindce1998/redhands.git && cd redhands
make build
sudo make install

# Install security tool dependencies (pick a profile)
sudo make install-tools PROFILE=minimal   # nmap, nuclei, httpx, subfinder
sudo make install-tools PROFILE=web       # web assessment tools
sudo make install-tools PROFILE=network   # network/infrastructure tools
sudo make install-tools PROFILE=ad        # Active Directory tools
sudo make install-tools PROFILE=k8s       # Kubernetes offensive tools
sudo make install-tools PROFILE=uefi      # UEFI bootkit simulation
sudo make install-tools PROFILE=telecom   # StaticZero telecom research (Linux only)
sudo make install-tools PROFILE=aegis     # Aegis-Shadow eBPF research (Linux only)
sudo make install-tools PROFILE=recon     # deep reconnaissance tools
sudo make install-tools PROFILE=all       # everything

# Check what's installed
make check-deps
```

### Windows (PowerShell)

```powershell
git clone https://github.com/yasindce1998/redhands.git; cd redhands
go build -o bin\redhands.exe .\cmd\redhands

# Install tool dependencies
.\scripts\install-tools.ps1 -Profile web
.\scripts\install-tools.ps1 -Check    # show what's installed/missing
```

### MCP Configuration

Add to your MCP client config:

**Claude Code** (`~/.claude/claude_desktop_config.json`), **Cursor** (`.cursor/mcp.json`), **VS Code** (`.vscode/mcp.json`):

```json
{
  "mcpServers": {
    "redhands": {
      "command": "redhands"
    }
  }
}
```

### Running

```bash
# stdio (default, for MCP clients)
redhands

# SSE transport (local CLI or remote use with TLS/auth)
REDHANDS_TRANSPORT=sse redhands  # loopback only; see secure remote setup below

# WebSocket transport
REDHANDS_TRANSPORT=ws redhands  # loopback only

# Docker (selected tools pre-installed)
docker compose run --rm -i redhands
```

### Installation Profiles

| Profile | Tools Included | Use Case |
|---------|---------------|----------|
| `minimal` | nmap, subfinder, httpx, nuclei | Quick recon and scanning |
| `web` | nmap, recon set (subfinder, amass, dig, waybackurls, gau, arjun), web set (httpx, katana, nikto, whatweb, testssl.sh), ffuf, gobuster, feroxbuster, masscan, rustscan, nuclei, sqlmap | Web application testing |
| `network` | nmap, masscan, rustscan, tshark, chisel, ligolo | Network/infrastructure |
| `ad` | nmap, impacket, certipy, crackmapexec, hashcat, john | Active Directory attacks |
| `k8s` | nmap, kubedagger-client, kubedagger-operator, kubedagger-server | Kubernetes offensive (eBPF) |
| `uefi` | barzakh-adversary, barzakh-scanner, barzakh-server | UEFI bootkit adversary simulation |
| `telecom` | staticzero-defense, staticzero-offense, modem-firmware, sdr-bridge | Telecom security research (eBPF, Linux only) |
| `aegis` | aegis-shadow-defense, aegis-shadow-offense | Linux eBPF security research (Aegis-Shadow) |
| `recon` | recon set (subfinder, amass, dig, waybackurls, gau, arjun) + web set (httpx, katana, nikto, whatweb, testssl.sh) | Deep reconnaissance |
| `all` | Everything | Full offensive toolkit |

Profiles describe desired dependencies, not a guarantee every dependency is available
on every OS. RustScan, testssl.sh, and CrackMapExec currently need manual installation;
KubeDagger client is Linux-only. Installers report missing tools rather than downloading
unverified replacements. See [dependency maintenance](docs/dependencies.md).

### Command-line client

`make build` produces `redhands`, `redhands-cli`, and `redhands-creds` in `bin/`.
The CLI uses the same authenticated SSE transport as MCP clients:

```sh
# Terminal 1
REDHANDS_TRANSPORT=sse ./bin/redhands
# Terminal 2
./bin/redhands-cli tools
./bin/redhands-cli targets add 192.0.2.1 lab-host
./bin/redhands-cli status
```

For HTTPS, set `REDHANDS_URL=https://your-server:8443`, `REDHANDS_API_KEY`, and
`REDHANDS_CLIENT_CA=/path/to/ca.pem`. For mTLS, also set `REDHANDS_CLIENT_CERT`
and `REDHANDS_CLIENT_KEY`. The CLI rejects untrusted certificates, redirects, and
non-loopback plain HTTP. `REDHANDS_CLIENT_TIMEOUT` sets its total deadline (default `6m`).
Tool failures return a nonzero exit status; calls are never retried automatically.

## Requirements

- Go 1.26.11+ (for building from source; if using Go 1.27, use 1.27.4+)
- Security tools on PATH (installed via scripts above, Docker, or manually)

## Available Tools

277 tools are registered across 32 toolsets. A default startup serves 270 of
them: the two credstore tools additionally require `REDHANDS_CREDSTORE_KEY`,
and the five GoPhish phishing tools additionally require `REDHANDS_GOPHISH_*`
environment variables.

### Nmap (toolset: `nmap`)

| Tool | Description |
|------|-------------|
| `nmap_port_scan` | TCP/UDP port scanning (SYN, connect, UDP) |
| `nmap_service_detect` | Service and version detection (-sV) |
| `nmap_os_detect` | OS fingerprinting (-O) |
| `nmap_vuln_scan` | NSE vulnerability scripts |

### Recon (toolset: `recon`)

| Tool | Description |
|------|-------------|
| `subfinder_enum` | Subdomain enumeration from passive sources |
| `amass_enum` | Network mapping and ASN discovery (OWASP Amass) |
| `dns_lookup` | DNS record queries via dig (A, AAAA, MX, NS, TXT, etc.) |
| `waybackurls` | Fetch archived URLs from the Wayback Machine |
| `gau_urls` | Fetch URLs from AlienVault OTX, Wayback, CommonCrawl, URLScan |
| `arjun_discover` | HTTP parameter discovery (hidden GET/POST params) |

### Web (toolset: `web`)

| Tool | Description |
|------|-------------|
| `httpx_probe` | HTTP service probing with tech detection |
| `katana_crawl` | Next-gen web crawler (JS crawling, headless) |
| `nikto_scan` | Web server vulnerability scanner |
| `whatweb_fingerprint` | Web technology fingerprinting |
| `testssl_scan` | TLS/SSL encryption testing |

### Fuzzing (toolset: `fuzz`)

| Tool | Description |
|------|-------------|
| `ffuf_fuzz` | Web fuzzing (dirs, params, vhosts) |
| `gobuster_dir` | Directory/file brute-forcing |
| `feroxbuster_scan` | Recursive content discovery (forced browsing) |

### Scanning (toolset: `scan`)

| Tool | Description |
|------|-------------|
| `masscan_scan` | Internet-scale port scanning (10M pps) |
| `rustscan_scan` | Modern fast port scanner (all 65535 ports in seconds) |

### Exploit (toolset: `exploit`)

| Tool | Description |
|------|-------------|
| `sqlmap_scan` | Automatic SQL injection detection and exploitation |

### Vulnerability (toolset: `vuln`)

| Tool | Description |
|------|-------------|
| `nuclei_scan` | Template-based vulnerability scanning |

### Impacket (toolset: `impacket`)

| Tool | Description |
|------|-------------|
| `impacket_secretsdump` | Dump SAM/LSA/NTDS.dit secrets |
| `impacket_psexec` | PsExec-style remote execution |
| `impacket_wmiexec` | WMI-based remote execution |
| `impacket_smbclient` | SMB client operations |
| `impacket_dcomexec` | DCOM remote execution |
| `impacket_get_tgt` | Request Kerberos TGT |
| `impacket_get_st` | Request service ticket (Kerberoast/delegation) |
| `impacket_ntlmrelay` | NTLM relay attack |

### Sliver C2 (toolset: `sliver`)

| Tool | Description |
|------|-------------|
| `sliver_generate` | Generate implant (mTLS, HTTP/S, DNS, WireGuard) |
| `sliver_listeners` | Manage C2 listeners |
| `sliver_sessions` | List/interact with sessions |
| `sliver_beacons` | List/interact with beacons |
| `sliver_execute` | Execute commands on implant |
| `sliver_upload` | Upload files to implant |
| `sliver_download` | Download files from implant |
| `sliver_pivot` | Pivot setup and management |
| `sliver_portfwd` | Port forwarding through implant |

### Tunneling (toolset: `tunnel`)

| Tool | Description |
|------|-------------|
| `chisel_server` | Start Chisel reverse tunnel endpoint |
| `chisel_client` | Chisel client (forward/reverse/SOCKS) |
| `ligolo_start` | Start Ligolo-ng proxy server |
| `ligolo_route` | Add routes through Ligolo tunnel |
| `ligolo_listener` | Manage Ligolo listeners on agent |

### Password Cracking (toolset: `crack`)

| Tool | Description |
|------|-------------|
| `hashcat_crack` | Crack hashes (dictionary, rules, masks) |
| `hashcat_benchmark` | Benchmark hash types |
| `hashcat_show` | Show cracked from potfile |
| `john_crack` | Crack passwords with John the Ripper |
| `john_show` | Show cracked passwords |
| `john_formats` | List supported hash formats |

### CrackMapExec (toolset: `crackmapexec`)

| Tool | Description |
|------|-------------|
| `cme_smb` | SMB enumeration/exec/pass-the-hash |
| `cme_winrm` | WinRM execution |
| `cme_ldap` | LDAP enumeration |
| `cme_mssql` | MSSQL queries/execution |
| `cme_ssh` | SSH credential spray/exec |

### Certipy (toolset: `certipy`)

| Tool | Description |
|------|-------------|
| `certipy_find` | Find AD CS templates and CAs |
| `certipy_req` | Request certificates |
| `certipy_auth` | Authenticate via PKINIT |
| `certipy_shadow` | Shadow credentials attack |
| `certipy_forge` | Golden certificate forgery |
| `certipy_relay` | NTLM relay to AD CS |

### tshark (toolset: `tshark`)

| Tool | Description |
|------|-------------|
| `tshark_capture` | Capture packets (interface, filter, duration) |
| `tshark_read` | Read pcap with display filter |
| `tshark_stats` | Protocol statistics |
| `tshark_extract` | Extract fields from captures |
| `tshark_follow` | Follow TCP/UDP/HTTP streams |

### KubeDagger (toolset: `kubedagger`)

| Tool | Description |
|------|-------------|
| 69 tools | eBPF-powered Kubernetes offensive toolkit, including managed C2-server lifecycle (`kubedagger_server_*`) — see `tools/kubedagger/` |

### Barzakh (toolset: `barzakh`)

| Tool | Description |
|------|-------------|
| `barzakh_list` | List available UEFI bootkit payload types (134 payloads) |
| `barzakh_generate` | Generate a UEFI bootkit payload for adversary simulation (x86-64, aarch64, riscv64, power64, armv7) |
| `barzakh_corpus` | Generate full test corpus of malicious/clean firmware pairs |
| `barzakh_scan` | Scan firmware images with 138 specialized bootkit detectors (exit 1 = detection, reported as a finding) |
| `barzakh_validate` | Validate detector coverage (TPR/FPR) against a corpus |
| `barzakh_scenario` | List/show/run multi-stage ATT&CK-mapped attack chains (6 bundled) |
| `barzakh_robustness` | Mutation-based detector evasion benchmark |
| `barzakh_detectors` | List/describe the 138 detectors |
| `barzakh_baseline` | Create/show firmware baselines |
| `barzakh_intel` | Query IOC feeds, MISP, ATT&CK, STIX intel |
| `barzakh_server_start` | Start the Barzakh REST scanner server as a managed background daemon (X-API-Key auth, SQLite history) |
| `barzakh_server_stop` | Stop a managed Barzakh server |
| `barzakh_server_status` | Status of managed Barzakh servers |
| `barzakh_inject` | ⚠️ Implant a payload into an existing firmware image (adversary simulation; approval-gated) |
| `barzakh_esp_build` | ⚠️ Build a bootable FAT16 ESP containing the payload as \EFI\BOOT\BOOTX64.EFI |
| `barzakh_qemu` | Boot firmware in an emulated QEMU/OVMF environment (run config / memory dump) |
| `barzakh_range` | Boot QEMU/OVMF/swTPM cyber-range suites with assert-on-detection (exit 1 = failed assertions, surfaced as a result) |
| `barzakh_fuzz` | Protocol-aware firmware fuzzing (dhcpv6/bmp/capsule/httpboot/tcg/hii) |
| `barzakh_history` | Query the SQLite scan history (list/show/diff/trends) |
| `barzakh_kb` | Manage the firmware knowledge base (add/list/search/export/import) |
| `barzakh_ml` | Train/evaluate the ML anomaly models |
| `barzakh_manifest_validate` | Validate detectors against a labeled corpus manifest with train/validation/test splits |
| `barzakh_info` | Scanner build/version, detector, architecture, and format metadata |
| `barzakh_report` | Generate report files (json/html/markdown/sarif/csv/ecs/cef/leef) from scan results |

### Telecom (toolset: `telecom`)

Wraps StaticZero, an eBPF telecom security research framework (2G–5G, satellite,
baseband firmware). Authorized lab use only.

> [!WARNING]
> `telecom_offense_start` launches the **telecom interception research loader**
> (features F89–F172: IMSI targeting, GTP/SS7/Diameter interception, RF and
> satellite domains). Intercepting telecommunications is **illegal without
> authorization in most jurisdictions — including in labs in some**. Use only
> in an isolated lab environment with equipment you own, and only where you
> hold explicit permission. The tool is approval-gated and requires root.

| Tool | Description |
|------|-------------|
| `telecom_doctor` | Read-only StaticZero defense engine preflight (platform/kernel/BPF checks) |
| `telecom_firmware_analyze` | Static vulnerability analysis of modem/baseband firmware images |
| `telecom_firmware_extract` | Extract firmware components with manifest |
| `telecom_firmware_diff` | Diff two firmware images |
| `telecom_firmware_nv_dump` | Extract NV items (carrier/band/security config) |
| `telecom_firmware_patch` | ⚠️ Patch baseband firmware images (regulated; device-destructive if flashed; approval-gated) |
| `telecom_firmware_monitor` | Monitor a modem device protocol stream (diag/at/qmi/mbim; bounded by the execution timeout) |
| `telecom_sdr_scan` | Receive-only LTE cell scan via SDR |
| `telecom_sdr_capture` | Receive-only IQ capture via SDR |
| `telecom_sdr_inject` | ⚠️ RF transmission (FCC/CEPT licensing; shielded/cabled lab use only; approval-gated) |
| `telecom_sdr_relay` | ⚠️ RF receive-and-retransmit relay (same RF warnings) |
| `telecom_sdr_selftest` | ⚠️ SDR TX pipeline self-test (same RF warnings) |
| `telecom_threats` | Correlated threats from a running defense engine |
| `telecom_alerts` | Raw alerts from a running defense engine |
| `telecom_stats` | Engine runtime statistics |
| `telecom_defense_start` | Start the StaticZero defense engine as a managed background daemon (JSON alerts stream to a file) |
| `telecom_defense_stop` | Stop a managed defense engine daemon |
| `telecom_defense_status` | Status of managed defense engine daemons |
| `telecom_offense_start` | ⚠️ Launch the StaticZero telecom interception research loader as a managed daemon (F89–F172; regulated; lab use only) |
| `telecom_offense_stop` | Stop a managed offense loader daemon |
| `telecom_offense_status` | Status of managed offense loader daemons |
| `telecom_correlator_start` | Start the protocol correlator as a managed daemon (JSON-lines event ingest on loopback) |
| `telecom_correlator_stop` | Stop a managed correlator daemon |
| `telecom_correlator_status` | Status of managed correlator daemons |

StaticZero binaries ship as checksum-verified release assets (v0.5.0, Linux
only, eBPF embedded) and install via the `telecom` profile:
`sudo make install-tools PROFILE=telecom`.

### Aegis-Shadow (toolset: `aegis`)

Wraps Aegis-Shadow, a Linux eBPF security research platform (educational, VM-only).
The analysis tools never execute binaries; `aegis_offense_plan` renders the manual
lab command with risk notes without executing it. The defense engine and the
offense rootkit loader can each be started as a managed background daemon
(approval-gated).

> [!DANGER]
> `aegis_offense_start` launches the **eBPF rootkit loader** — process hiding,
> credential harvesting, log tampering, anti-forensics, and covert C2, running
> at kernel level with root. Two capabilities are **destructive by design**:
> `deadman_switch` (scorched-earth wipe triggered on tamper or timeout — the
> VM may become unrecoverable) and `wipe_bytecode` (erases the loaded eBPF
> bytecode from memory, defeating live forensics). Both are opt-in, emit loud
> warnings in every result, and expect a **disposable, snapshotted lab VM**.
> Data loss from these flags is expected behavior, not a bug.

| Tool | Description |
|------|-------------|
| `aegis_alerts_parse` | Parse/filter NDJSON alert files from the defense engine |
| `aegis_alerts_tail` | Tail the last N alerts from an alert file |
| `aegis_modules_list` | Reference catalog of defense modules and offense features |
| `aegis_defense_config_read` | Read/validate a defense engine hot-reload config |
| `aegis_defense_config_write` | Write a defense engine config (threshold, window) |
| `aegis_offense_plan` | Dry-run planner: validate offense feature flags and render the exact manual command line with risk notes |
| `aegis_defense_start` | Start the Aegis-Shadow defense engine as a managed background daemon (NDJSON alerts stream to a file; requires root) |
| `aegis_defense_stop` | Stop a managed defense engine daemon |
| `aegis_defense_status` | Status of managed defense engine daemons |
| `aegis_offense_start` | ☠️ Launch the Aegis-Shadow eBPF rootkit loader as a managed daemon (destructive `deadman_switch`/`wipe_bytecode` are opt-in with warnings; disposable VM only) |
| `aegis_offense_stop` | Stop a managed offense loader daemon |
| `aegis_offense_status` | Status of managed offense loader daemons |
| `aegis_c2_send` | ☠️ Send a command to a running rootkit over its encrypted C2 channel (hide/unhide pid, obfuscate file, exfil, kill-switch; fire-and-forget; requires the `aegis-c2` CLI from Aegis-Shadow ≥ v0.2.0) |

### Metasploit (toolset: `msf`)

Wraps Metasploit Framework (msfvenom + msfconsole). Console tools generate
validated `.rc` resource files from structured parameters — never
`msfconsole -x` — so console-command injection is structurally impossible.
Metasploit is not checksum-pinnable (no stable release binaries); install it
manually (`apt install metasploit-framework` on Kali/Parrot) and the allowlist
discovers `msfconsole`/`msfvenom` on PATH. msfconsole startup takes 10–60s;
runs are bounded by `REDHANDS_TIMEOUT`.

| Tool | Description |
|------|-------------|
| `msf_payload_generate` | ⚠️ Generate Metasploit payloads via msfvenom (formats, encoders, platforms; reports SHA-256 of the artifact; approval-gated) |
| `msf_payload_list` | List payloads, encoders, formats, platforms, or architectures |
| `msf_module_info` | Show module documentation (exploit/auxiliary/post/payload/encoder/nop) |
| `msf_module_run` | ⚠️ Run a module against targets (options map, run/exploit/exploit -j; scope-checked by the engagement middleware; approval-gated) |
| `msf_resource_run` | ⚠️ Run an operator-authored `.rc` resource file (arbitrary console commands; approval-gated) |

### System

| Tool | Description |
|------|-------------|
| `redhands_health` | Server health check and binary dependency status |

## Transports

RedHands supports four transport modes:

| Transport | Use Case | Config |
|-----------|----------|--------|
| **stdio** (default) | Local use with Claude Code, Cursor, VS Code | `REDHANDS_TRANSPORT=stdio` |
| **HTTP** (Streamable) | Modern MCP `2026-07-28` clients: stateless single-endpoint JSON-RPC | `REDHANDS_TRANSPORT=http` (`REDHANDS_HTTP_ADDR`, default `127.0.0.1:8082`; `REDHANDS_HTTP_PATH`, default `/mcp`) |
| **SSE** | Legacy HTTP clients (deprecated-era transport) | `REDHANDS_TRANSPORT=sse` (loopback by default) |
| **WebSocket** | Real-time bidirectional (custom transport) | `REDHANDS_TRANSPORT=ws` (loopback by default) |

The HTTP transport implements the modern spec: POST-only `/mcp` endpoint,
required `MCP-Protocol-Version`/`Mcp-Method` (and `Mcp-Name` for `tools/call`)
headers validated against the body, `405` for GET/DELETE, `404`+`-32601` for
unknown methods, `202` for notifications, and per-request `_meta` protocol
version validation (`-32022` with the supported list). Legacy clients that
open with `initialize` are served by the dual-era handshake on every
transport. Non-loopback listeners require authentication **and TLS**.

## Authentication

| Mode | Config | Description |
|------|--------|-------------|
| **none** (default) | `REDHANDS_AUTH=none` | No authentication |
| **API key** | `REDHANDS_AUTH=apikey` + `REDHANDS_API_KEY=<secret>` | `X-API-Key` header validation |
| **mTLS** | `REDHANDS_AUTH=mtls` + cert/key/CA env vars | Client certificate verification |

## Tool Chaining (Workflows)

Chain tools sequentially with variable substitution:

```json
{
  "method": "workflow/run",
  "params": {
    "steps": [
      {"tool": "nmap_port_scan", "params": {"target": "10.0.0.1"}},
      {"tool": "nuclei_scan", "params": {"target": "http://10.0.0.1"}}
    ]
  }
}
```

Variables: `$prev.text` (previous step output), `$step[N].text` (Nth step output).
Substitutions contain the full formatted text, not extracted targets; only pass them
to parameters that accept that format. All steps honor dry-run, rate limits and scope.

## Campaigns (Multi-Stage Attack Framework)

Campaigns extend workflows with **conditions**, **parallel fan-out**, **failure
recovery (`goto:`)**, **checkpointing**, **resume**, **cancellation**, and
**playbook templates**. Every step executes through the same middleware chain
as a direct `tools/call` (audit, auth, rate limits, scope, dry-run, approval,
concurrency limits).

```json
{
  "method": "campaign/run",
  "params": {
    "id": "web-engage-1",
    "name": "Web assessment",
    "steps": [
      {"id": "portscan", "tool": "nmap_port_scan", "params": {"target": "10.0.0.1"}},
      {"id": "webscan", "tool": "nuclei_scan", "params": {"target": "http://10.0.0.1"}},
      {"parallel": [
        {"id": "nikto", "tool": "nikto_scan", "params": {"target": "http://10.0.0.1"}},
        {"id": "tls", "tool": "testssl_scan", "params": {"target": "10.0.0.1:443"}}
      ], "on_fail": "continue"},
      {"id": "report", "tool": "loot_add", "params": {"description": "done"}}
    ]
  }
}
```

### Step fields

| Field | Description |
|-------|-------------|
| `id` | Unique step identifier used by conditions and `${id...}` references |
| `tool` / `params` | Tool name and JSON params (exactly like `tools/call`) |
| `parallel` | Array of sub-steps executed concurrently (≤16, no nesting) |
| `condition` | Skip the step unless the condition holds |
| `on_fail` | `stop` (default), `continue`, or `goto:<step_id>` recovery jump |

### Conditions

```json
{"condition": {"step": "portscan", "op": "json_gt", "path": "hosts.0.ports.0", "value": "0"}}
```

Operators: `success`, `failure`, `contains`, `not_contains`, `equals`, `not_equals`,
plus JSON-aware `json_exists`, `json_not_exists`, `json_equals`, `json_not_equals`,
`json_contains`, `json_gt`, `json_lt` evaluated against a previous step's structured
output (`step` may be a step ID, `"$prev"`, or a zero-based index).

### Structured dataflow

Placeholders can extract **fields** from prior results, not just whole text.
Tools emitting JSON (raw or in a markdown ```json fence) are queryable by
dot-path with numeric array indices:

```
$prev.text                     full text of the previous step
$prev.json.findings.0.severity field extraction
$step[2].json.hosts            whole array from step 2 (native type preserved)
${portscan.json.hosts.0.ip}    reference by step ID
```

A placeholder that makes up an entire string value is substituted natively
(numbers stay numbers, arrays stay arrays); placeholders embedded in a larger
string are substituted as text. Unresolvable placeholders pass through untouched.

### Auto-populating the target database

`record` rules map JSON arrays in a step's output to target database entries,
so campaigns build the host/service/credential/finding picture automatically:

```json
{
  "id": "discover",
  "tool": "kubedagger_k8s_discover",
  "params": {"namespace": "default"},
  "mitre": ["T1613"],
  "record": [
    {"type": "host", "path": "nodes", "fields": {"ip": "ip", "hostname": "name", "os": "os"}},
    {"type": "host", "path": "pods", "fields": {"ip": "pod_ip", "hostname": "name"}}
  ]
}
```

Entry types: `host`, `service`, `credential`, `finding`. Recorded entries are
tagged `campaign:<workflow_id>` and become queryable via the `targetdb_*` tools
and the attack graph. Recording failures warn in the step result without
failing the campaign.

### MITRE ATT&CK tagging

Steps accept `mitre: ["T1613", "T1552.001"]` technique tags. Campaign results
aggregate the unique techniques of executed steps as `mitre_techniques`, which
can be passed to `kubedagger_detection` (`action: "generate"`, `techniques` as
a comma-separated list) to produce matching Falco/Sigma/audit detection rules.
The shipped `k8s-recon-chain` playbook demonstrates recording and tagging end
to end, including a final detection-rule generation step.

### Campaign lifecycle

| Method | Params | Description |
|--------|--------|-------------|
| `campaign/run` | steps or `template`+`vars` | Execute a campaign synchronously; checkpoints every step |
| `campaign/start` | same as `campaign/run` | **Async**: with the Tasks extension declared, returns a `CreateTaskResult` (taskId, ttlMs, pollIntervalMs) and runs detached from the request; without it, identical to `campaign/run`. Idempotent: re-starting a running ID returns the live task |
| `campaign/status` | `workflow_id` | Load persisted state |
| `campaign/list` | — | List all saved campaigns |
| `campaign/resume` | `workflow_id` | Continue a paused/cancelled campaign |
| `campaign/cancel` | `workflow_id` | Cancel a running campaign (works cross-replica: the engine re-reads persisted state at each checkpoint) |
| `campaign/templates` | — | List playbook templates |
| `campaign/template/get` | `name` | Fetch one template |
| `campaign/template/save` | template JSON | Validate and persist a playbook |
| `tasks/get` | `taskId` | Poll a task: `working`/`input_required`/`completed`/`failed`/`cancelled`; terminal states carry the result or error |
| `tasks/cancel` | `taskId` | Cooperatively cancel a task (acks immediately) |
| `tasks/update` | `taskId`, `inputResponses` | Submit approval responses for a paused task (`approval` for a sequential gate, `approval-<sub_step_id>` per gated sub-step inside a parallel group; unknown keys are acked and ignored) |

Campaigns interrupted mid-step (cancellation or timeout) checkpoint as
`paused` and re-run the interrupted step on resume. Every campaign is
single-writer (an advisory flock per workflow ID): a duplicate start of a
running campaign returns its live task instead of corrupting the checkpoint.

### Approval gating (MRTR)

Tools that require operator approval (high-impact tools not listed in
`REDHANDS_APPROVED_TOOLS`) no longer need to block. When the request declares
the Tasks extension, an approval-gated `tools/call` answers with
`resultType: "input_required"` and an `elicitation/create` approval request;
the client re-issues the same call with `inputResponses: {"approval":
{"approved": true}}` and the single call executes (audited as an approval
bypass). Inside a task-tracked campaign, an approval-gated step pauses the
task (`input_required` via `tasks/get`), the response arrives through
`tasks/update`, and `campaign/resume` re-runs the step. Requests without the
capability fail closed with the classic message. Responses never ride in
tool arguments — only in the dedicated `inputResponses` field.

Parallel groups use the same machinery per sub-step instead of failing the
gated sub-step outright: when one or more sub-steps of a group trip approval
gates, the campaign pauses ONCE and `tasks/get` shows one inputRequest per
gated sub-step, keyed `approval-<sub_step_id>`. Answer each individually
(`tasks/update` with `inputResponses: {"approval-<sub_step_id>":
{"approved": true}}`; unknown or stale keys are acked and ignored). On
`campaign/resume` the group replays partially: sub-steps that already
completed are not re-executed, sub-steps that failed for other reasons keep
their recorded failure, approved sub-steps re-run once with their own
one-call bypass, denied sub-steps fail with `approval denied` and flow
through the group's `on_fail` (stop/continue/goto), and unanswered gates
re-trip with fresh request ids. A `goto` that re-enters a group is a fresh
execution — the per-run completion set resets and every sub-step re-runs.
Capability-less requests keep the classic fail-closed behavior for group
sub-steps too.

### Playbooks

Playbooks are reusable, versioned campaign templates stored as JSON in
`REDHANDS_WORKFLOW_TEMPLATES_DIR` (default `./playbooks/`). Shipped examples:
`recon-to-vuln`, `web-assessment`, `k8s-recon-chain`, `ad-kerberoast-chain`,
`firmware-bootkit-assessment`, `telecom-defense-monitoring`,
`firmware-purple-team`. Point-and-shoot a playbook:

```json
{
  "method": "campaign/run",
  "params": {
    "template": "recon-to-vuln",
    "vars": {"domain": "target.example", "severity": "critical,high"}
  }
}
```

### Engagement-scoped campaigns

Campaigns can bind to an engagement with the `engagement` parameter. The named
engagement must exist and be the **active** engagement — the campaign fails
fast instead of silently running against the wrong scope, and every step's
targets are checked against that engagement's scope by the middleware:

```json
{
  "method": "campaign/run",
  "params": {
    "engagement": "lab-1",
    "template": "web-assessment",
    "vars": {"target": "https://target.example"}
  }
}
```

Bindings are persisted with the campaign state and re-validated on resume, so
switching engagements between runs rejects a stale binding.

Limits: 128 steps per campaign, 16 steps per parallel group, 64 `goto` recovery
jumps, 16 MiB cumulative output — mirroring workflow hard caps.

## Structured Output Parsing

Built-in parsers for common tool output formats:

- **Nmap XML** — parses `-oX` output into structured hosts/ports/services
- **Nuclei JSON** — parses JSONL findings into severity-grouped results
- **Masscan JSON** — parses `-oJ` output into host/port pairs

## Report Generation

Generate reports from workflow results:

```json
{
  "method": "report/generate",
  "params": {
    "format": "markdown",
    "title": "Assessment report",
    "sections": [{"title": "Summary", "tool": "nmap_port_scan", "content": "Reviewed scan results"}]
  }
}
```

Formats: `markdown` (.md) and `html` (self-contained with inline CSS).

## Plugin System

Define custom tools via JSON without writing Go:

```json
{
  "name": "custom_quick_scan",
  "description": "Quick nmap top-100 scan",
  "binary": "nmap",
  "args_template": ["-sS", "--top-ports", "100", "{{.target}}"],
  "input_schema": {
    "type": "object",
    "properties": {
      "target": {"type": "string", "description": "Target IP or hostname"}
    },
    "required": ["target"]
  }
}
```

Drop JSON files in `REDHANDS_PLUGINS_DIR` (default `./plugins/`) and they appear in `tools/list` automatically.

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDHANDS_TOOLSETS` | (all) | Comma-separated toolsets to register (approval still applies) |
| `REDHANDS_TIMEOUT` | `5m` | Execution timeout per tool call |
| `REDHANDS_MAX_OUTPUT` | `10485760` | Max output bytes per execution (10MB) |
| `REDHANDS_RATE_LIMIT` | `10` | Token bucket refill rate (requests/sec) |
| `REDHANDS_RATE_BURST` | `20` | Token bucket burst capacity |
| `REDHANDS_CACHE_TTL` | `5m` | Result cache TTL |
| `REDHANDS_CACHE_SIZE` | `100` | Max pure-function results (oldest-expiry eviction) |
| `REDHANDS_AUDIT_FILE` | `audit.jsonl` | Audit log file path |
| `REDHANDS_TRANSPORT` | `stdio` | Transport mode: `stdio`, `sse`, or `ws` |
| `REDHANDS_SSE_ADDR` | `127.0.0.1:8080` | SSE HTTP listen address |
| `REDHANDS_WS_ADDR` | `127.0.0.1:8081` | WebSocket listen address |
| `REDHANDS_AUTH` | `none` | Auth mode: `none`, `apikey`, or `mtls` |
| `REDHANDS_API_KEY` | — | API key (required when auth=apikey) |
| `REDHANDS_TLS_CERT` | — | TLS certificate path |
| `REDHANDS_TLS_KEY` | — | TLS private key path |
| `REDHANDS_TLS_CA` | — | CA certificate for mTLS client verification |
| `REDHANDS_PLUGINS_DIR` | `./plugins` | Directory for JSON plugin definitions |
| `REDHANDS_PLUGIN_POLL_INTERVAL` | `5s` | Plugin directory polling interval |
| `REDHANDS_CREDSTORE_KEY` | — | Strong encryption key required for credential persistence |
| `REDHANDS_CREDSTORE_FILE` | `credstore.enc` | Encrypted credential store file |
| `REDHANDS_TARGETDB_FILE` | `targetdb.json` | Target database file |
| `REDHANDS_TARGETDB_AUTOSAVE` | `true` | Persist target database changes immediately |
| `REDHANDS_ENGAGEMENT_DIR` | `engagements` | Engagement metadata directory |
| `REDHANDS_DRY_RUN` | `false` | Preview executions without running tools |
| `REDHANDS_OPSEC_PROFILE` | — | OPSEC profile name (parsed; proxy routing not yet wired) |
| `REDHANDS_IOC_FILE` | — | Indicator-of-compromise list file (parsed; matching not yet wired) |
| `REDHANDS_TCP_ADDR` | — | TCP transport listen address; requires `REDHANDS_AUTH=apikey` (e.g. 127.0.0.1:8082) |
| `REDHANDS_DASHBOARD_ADDR` | — | Dashboard HTTP listen address (parsed; dashboard not yet wired) |
| `REDHANDS_GOPHISH_URL` | — | GoPhish API base URL (enables the phishing toolset) |
| `REDHANDS_GOPHISH_API_KEY` | — | GoPhish API key |
| `REDHANDS_MAX_CONCURRENT` | `4` | Maximum active tool calls across clients and workflows |
| `REDHANDS_MAX_QUEUED` | `16` | Maximum queued calls; further requests fail without executing |
| `REDHANDS_APPROVED_TOOLS` | — | Exact comma-separated names approved by the operator for high-impact/unclassified tools |
| `REDHANDS_WORKFLOW_TIMEOUT` | `30m` | Total deadline for a sequential workflow or campaign |
| `REDHANDS_WORKFLOW_STATE_DIR` | `workflow_state` | Campaign checkpoint directory |
| `REDHANDS_WORKFLOW_TEMPLATES_DIR` | `playbooks` | Playbook template directory |
| `REDHANDS_WORKFLOW_MAX_PARALLEL` | `4` | Max concurrent steps inside a campaign parallel group (≤32) |
| `REDHANDS_EVIDENCE_DIR` | `evidence` | Artifact directory with persistent metadata index |
| `REDHANDS_LOOT_DIR` | `loot` | Directory containing the atomic `loot.json` store |

Non-loopback listeners require authentication **and TLS**. API keys are accepted only
in the `X-API-Key` header. stdio uses local OS access controls, not API-key authentication.
Caching is limited to pure MITRE/risk-score lookups, never scans or state-changing tools.
High-impact, mixed-mode, and unclassified tools (including plugins) require explicit
operator approval via `REDHANDS_APPROVED_TOOLS`. Dry-run previews do not require this
approval and never execute tools. `tools/list` publishes policy metadata and MCP safety hints.
See [security and deployment notes](docs/security-hardening.md) for HTTPS/mTLS setup,
scope limitations, credential migration, and remaining release work.

### Evidence and loot

Evidence metadata persists in `REDHANDS_EVIDENCE_DIR/index.json`. Artifacts use random
IDs rather than host/tool text in filenames, and are checked against recorded size and
SHA-256 values when the store opens. Old files with no index remain untouched and are
not automatically listed. Corrupt metadata or missing/changed indexed artifacts stop
startup instead of silently losing their history.

Loot writes are atomic, and malformed `loot.json` files fail startup. Both stores are
single-process stores: do not point multiple servers at the same directories. Artifacts
and loot are private files, **not encrypted storage**; protect their directories and backups.

`evidence_screenshot` requires operator approval and `cutycapt` installed on PATH at
startup. It uses the shared executor, private staging, HTTP(S)-only URLs, and PNG
validation. CutyCapt may require a display/headless environment; it is not bundled in
the current Docker image. Browser redirects and subresources still need network isolation.

See [evidence and loot recovery](docs/evidence-storage.md) before moving stores,
repairing corrupt files, or handling legacy/unindexed artifacts.

### Toolset Filtering

Enable only specific toolsets:

```bash
# AD/internal assessment
export REDHANDS_TOOLSETS=nmap,impacket,crackmapexec,certipy,sliver,crack

# External web assessment
export REDHANDS_TOOLSETS=nmap,recon,web,fuzz,scan,vuln

# Network analysis
export REDHANDS_TOOLSETS=nmap,scan,tshark,tunnel

# Firmware + telecom research
export REDHANDS_TOOLSETS=barzakh,telecom,aegis

# All tools (default when unset)
export REDHANDS_TOOLSETS=
```

## Security

- **Binary allowlist** — only known security tools can be executed
- **Argument validation** — shell metacharacter rejection for external-tool arguments
- **Target validation and scope** — explicit network targets checked against active engagement scope; not a complete network sandbox
- **Destructive-capability posture** — tools that can destroy data or destroy
  a machine (`aegis_offense_start` with `deadman_switch` or `wipe_bytecode`)
  are opt-in, approval-gated, and emit loud warnings in every result; read the
  warnings in the [Aegis-Shadow](#aegis-shadow-toolset-aegis) and
  [Telecom](#telecom-toolset-telecom) sections before using the offense tools
- **Output size cap** — 10MB per execution
- **Execution timeout** — configurable per tool call
- **Rate limiting** — token bucket prevents abuse
- **Authentication** — API key or mTLS for remote transports
- **Audit logging** — direct calls and workflow steps logged as JSONL; logging failures reported to stderr

## Development

```bash
make build          # Build binary to bin/
make test           # Run tests with race detector
make lint           # Run golangci-lint
make docker         # Build Docker image
make install        # Install binary to /usr/local/bin
make install-tools  # Install security tools (PROFILE=minimal|web|network|ad|k8s|uefi|telecom|aegis|recon|all)
make check-deps     # Check which tools are available
```

Additional regression checks:

```sh
go vet ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

### Live binary tests

The wrapper unit tests build argv strings but verify them only against a
`MockExecutor`. When an upstream binary changes its CLI, nothing catches it —
the `tools/livecheck` suite does. It runs the **real** binaries and asserts
that the flags, subcommands and enum values the wrappers emit are still
accepted (help-text assertions plus safe dry-parses terminated by
`--help`/`--echo`; nothing scans a target or mutates state).

```sh
make test-live
# equivalent: go test -tags=livebin ./tools/livecheck/... -run TestLiveFlagSurface
```

Notes:

- The suite is gated behind the `livebin` build tag, so `go test ./...` and
  the normal CI jobs are unaffected.
- Binaries are discovered via `PATH`; a binary that is not installed is
  reported as `SKIP ... binary not on PATH`, never as a failure. The suite is
  safe to run on any machine.
- A check can also skip with a `KNOWN CLI DRIFT` / `SKIPPED (distro quirk)`
  message when the pinned or distro binary genuinely rejects the wrapper's
  argv (e.g. Ubuntu ships core john without the jumbo-only `--list`, and a
  broken whatweb package). Those skips are deliberate, printed in every run,
  and must lead to a wrapper fix or a dependency bump — never to deleting the
  check.
- In the Docker image (which ships ~25 pinned binaries but no Go toolchain),
  compile the suite on the host and run it inside the container, where the
  binaries live:

  ```sh
  CGO_ENABLED=0 go test -tags=livebin -c -o livecheck.test ./tools/livecheck/
  docker run --rm --network none -v "$PWD/livecheck.test:/usr/local/bin/livecheck.test:ro" \
    --entrypoint /usr/local/bin/livecheck.test redhands
  ```

  The `live-binaries` CI job instead installs a minimal binary set on
  ubuntu-latest (apt plus the checksum-verified pinned releases via
  `scripts/dependencies.py`) and runs `go test -tags=livebin` directly.
- When you change a wrapper's argv, update the matching entry in
  `tools/livecheck/table.go` so drift detection stays meaningful.

### Live end-to-end tests

Tier 1 (`tools/livecheck`) proves binaries still *accept* the wrappers' argv.
Tier 2 (`testdata/` golden fixtures) proves output *shapes*. The
`tools/e2e` suite (Tier 3) proves **real execution**: it drives JSON-RPC
`tools/call` and `campaign/run` requests into a fully wired in-process
server — the same `BinaryExecutor` (allowlist from `binaries.Discover()`),
the same middleware chain (audit to a temp file, rate limits, engagement
scope, approval gates, concurrency limiter), the same registry with builtin
tool policies, and the same campaign recorder as `cmd/redhands` — and
asserts on what the real binaries actually did.

```sh
make test-e2e
# equivalent: go test -tags=livee2e ./tools/e2e/...
```

Scenarios (all skip cleanly when their binary is missing):

- **Barzakh purple-team loop (offline, deterministic)** — `barzakh_corpus`
  generates a corpus into a temp dir, `barzakh_scan` scans one malicious
  sample (scanner exit 1 = bootkit detected must surface as a *result* with
  the severity summary rendered), `barzakh_validate` validates the corpus.
- **Campaign with real execution and record rules** — a `campaign/run`
  whose steps execute the real corpus+scan tools through the middleware
  chain; the scan step's finding record rule persists the scanner's real
  `findings` array into the target database, asserted via the store.
- **nmap against a test-owned listener** — the suite opens a
  `127.0.0.1:0` listener and runs `nmap_port_scan` (connect scan; SYN
  needs root) and `nmap_service_detect` against that exact port.
- **nuclei with a test-authored template** — a minimal `http`-protocol
  template (static word matcher on a body the local test server always
  serves, severity `info`) is written to a temp file and passed via the
  `templates` parameter; nothing is downloaded.
- **telecom_doctor** — `staticzero-defense --doctor --json`: asserts the
  DoctorReport renders with a checks array and the `ebpf_object` check
  passes (the release binary embeds the eBPF object); privilege failures
  are expected and fine.
- **telecom_firmware_analyze** — a synthetic modem image (documented
  fixture generator with a fixed seed for the padding) analyzed with
  `modem-firmware analyze`; asserts the vulnerability report, its findings
  (strcpy, weak ciphers, debug interfaces), and the written report file.
- **kubedagger_k8s_discover against no cluster** — only asserts the call
  returns a well-formed response without hanging (the wrapper's
  empty-stdout handling is intentionally not pinned). `HOME` is redirected
  so the client cannot pick up a developer's real kubeconfig.

Safety rules enforced by the suite:

- The only network targets are `127.0.0.1`/localhost listeners the test
  itself owns; there is no network egress beyond the local binaries' own
  startup.
- Everything deterministic: `:0` listeners, fixed seeds for synthetic
  inputs, temp dirs, bounded polling (no sleeps) for the async audit log.
- Gated behind the `livee2e` build tag, so `go test ./...` and the normal
  CI jobs are unaffected.
- Executing tools are pre-approved in the harness config exactly like a
  reviewed `REDHANDS_APPROVED_TOOLS` setup, so the approval middleware
  itself is exercised (not bypassed).

The `live-e2e` CI job installs the scenario binaries (nmap via apt; nuclei
via the pinned `go install`; barzakh, StaticZero, and KubeDagger binaries
via the checksum-verified pinned releases in `scripts/dependencies.json`)
and runs `go test -tags=livee2e ./tools/e2e/...`. When you add a scenario
that needs a new binary, add it to that job's install steps.

## Docker

```bash
# Build and run
docker build -t redhands .
docker run -i redhands

# With Docker Compose (local stdio mode; no published ports)
docker compose run --rm -i redhands

# With authentication
# Requires tls/server.crt, tls/server.key, and a strong REDHANDS_API_KEY
docker compose --profile secure up redhands-secure
```

The Docker image includes a subset of supported security tools (check dependencies
before use; some tools require additional installation or privileges):
- **apt/source**: nmap, masscan, tshark, hashcat, john, nikto, whatweb
- **pip**: impacket, certipy-ad
- **Go tools**: subfinder, httpx, nuclei, ffuf, katana, gobuster, gau, waybackurls
- **Releases**: chisel, ligolo-ng, kubedagger (client, operator, server v0.5.0), barzakh (adversary, scanner, server v0.7.0), staticzero (defense, modem-firmware, sdr-bridge v0.5.0), aegis-shadow-defense (v0.1.1)

## License

MIT

## Disclaimer

RedHands is provided for authorized security testing, education, and research purposes only. You are solely responsible for ensuring you have explicit, written permission before using this tool against any system, network, or application. Unauthorized access to computer systems is illegal and punishable under applicable law including the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent legislation worldwide.

The authors and contributors of RedHands accept no liability for misuse or damage caused by this software. Use responsibly and ethically.
