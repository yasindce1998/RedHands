<p align="center">
  <img src="docs/logo.png" alt="RedHands Logo" width="250" height="250"/>
</p>

<h1 align="center">RedHands</h1>

<p align="center">
  <strong>Enterprise-grade MCP server for offensive security tools</strong>
</p>

<p align="center">
  <a href="https://github.com/yasindce1998/redhands/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/yasindce1998/redhands/ci.yml?style=flat-square&logo=github&logoColor=white&label=CI&color=00c853" alt="CI"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.26+"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Compatible-ff2d2d?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjEwIiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiLz48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIzIi8+PC9zdmc+" alt="MCP Compatible"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-bf5fff?style=flat-square" alt="License: MIT"></a>
  <a href="https://github.com/yasindce1998/redhands"><img src="https://img.shields.io/badge/Tools-125-00fff2?style=flat-square" alt="125 Tools"></a>
</p>

<p align="center">
  Built in Go with zero external dependencies. Multi-transport (stdio/SSE/WebSocket), tool chaining,<br/>
  structured parsing, report generation, plugin system, rate limiting, caching, and audit logging.
</p>

```
go install github.com/yasindce1998/redhands/cmd/redhands@latest
```

## Quick Start

```bash
# Build
make build

# Run with Claude Code / Cursor / VS Code (stdio)
# Add to your MCP config:
{
  "mcpServers": {
    "redhands": {
      "command": "/path/to/redhands"
    }
  }
}

# Run with SSE transport (remote/team use)
REDHANDS_TRANSPORT=sse REDHANDS_SSE_ADDR=:8080 ./bin/redhands

# Run with WebSocket transport
REDHANDS_TRANSPORT=ws REDHANDS_WS_ADDR=:8081 ./bin/redhands

# Run with Docker
docker compose up
```

## Requirements

- Go 1.26+
- Security tools installed on PATH (see Available Tools below)

## Available Tools

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
| 57 tools | eBPF-powered Kubernetes offensive toolkit (see `tools/kubedagger/`) |

### System

| Tool | Description |
|------|-------------|
| `redhands_health` | Server health check and binary dependency status |

## Transports

RedHands supports three transport modes:

| Transport | Use Case | Config |
|-----------|----------|--------|
| **stdio** (default) | Local use with Claude Code, Cursor, VS Code | `REDHANDS_TRANSPORT=stdio` |
| **SSE** | Remote/team deployment over HTTP | `REDHANDS_TRANSPORT=sse` + `REDHANDS_SSE_ADDR=:8080` |
| **WebSocket** | Real-time bidirectional (raw frame protocol) | `REDHANDS_TRANSPORT=ws` + `REDHANDS_WS_ADDR=:8081` |

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
      {"tool": "nuclei_scan", "params": {"target": "$prev.text"}}
    ]
  }
}
```

Variables: `$prev.text` (previous step output), `$step[N].text` (Nth step output).

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
    "data": { ... }
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
| `REDHANDS_TOOLSETS` | (all) | Comma-separated toolsets to enable |
| `REDHANDS_TIMEOUT` | `5m` | Execution timeout per tool call |
| `REDHANDS_MAX_OUTPUT` | `10485760` | Max output bytes per execution (10MB) |
| `REDHANDS_RATE_LIMIT` | `10` | Token bucket refill rate (requests/sec) |
| `REDHANDS_RATE_BURST` | `20` | Token bucket burst capacity |
| `REDHANDS_CACHE_TTL` | `5m` | Result cache TTL |
| `REDHANDS_CACHE_SIZE` | `100` | Max cached results (LRU eviction) |
| `REDHANDS_AUDIT_FILE` | `audit.jsonl` | Audit log file path |
| `REDHANDS_TRANSPORT` | `stdio` | Transport mode: `stdio`, `sse`, or `ws` |
| `REDHANDS_SSE_ADDR` | `:8080` | SSE HTTP listen address |
| `REDHANDS_WS_ADDR` | `:8081` | WebSocket listen address |
| `REDHANDS_AUTH` | `none` | Auth mode: `none`, `apikey`, or `mtls` |
| `REDHANDS_API_KEY` | — | API key (required when auth=apikey) |
| `REDHANDS_TLS_CERT` | — | TLS certificate path |
| `REDHANDS_TLS_KEY` | — | TLS private key path |
| `REDHANDS_TLS_CA` | — | CA certificate for mTLS client verification |
| `REDHANDS_PLUGINS_DIR` | `./plugins` | Directory for JSON plugin definitions |

### Toolset Filtering

Enable only specific toolsets:

```bash
# AD/internal assessment
export REDHANDS_TOOLSETS=nmap,impacket,crackmapexec,certipy,sliver,crack

# External web assessment
export REDHANDS_TOOLSETS=nmap,recon,web,fuzz,scan,vuln

# Network analysis
export REDHANDS_TOOLSETS=nmap,scan,tshark,tunnel

# All tools (default when unset)
export REDHANDS_TOOLSETS=
```

## Security

- **Binary allowlist** — only known security tools can be executed
- **Shell metacharacter rejection** on all inputs
- **Target validation** — strict format checks for IPs, domains, URLs
- **Output size cap** — 10MB per execution
- **Execution timeout** — configurable per tool call
- **Rate limiting** — token bucket prevents abuse
- **Authentication** — API key or mTLS for remote transports
- **Full audit trail** — every tool invocation logged as JSONL

## Development

```bash
make build      # Build binary to bin/
make test       # Run tests with race detector
make lint       # Run golangci-lint
make docker     # Build Docker image
```

## Docker

```bash
# Build and run
docker build -t redhands .
docker run -i redhands

# With Docker Compose (SSE mode)
docker compose up

# With authentication
REDHANDS_API_KEY=mysecret docker compose --profile secure up
```

The Docker image includes all supported security tools pre-installed:
- **apt**: nmap, masscan, tshark, hashcat, john, nikto, whatweb
- **pip**: impacket, certipy-ad, crackmapexec
- **Go tools**: subfinder, httpx, nuclei, ffuf, katana, gobuster, gau
- **Releases**: chisel, ligolo-ng

## License

MIT
