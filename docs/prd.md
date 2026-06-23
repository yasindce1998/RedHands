# RedHands — Product Requirements Document

## Overview

RedHands is an MCP (Model Context Protocol) server that exposes offensive security tools to AI agents. It follows the same architecture patterns used by GitHub's MCP server and Atlassian's MCP server — a single-binary Go server that starts with stdio transport, groups tools into logical toolsets, and delegates auth to the MCP host via environment variables.

**Current state:** v0.3.0 shipped with stdio transport, 23 tools across 7 toolsets, secure binary execution, rate limiting, result caching, and structured audit logging.

---

## Design Principles

1. **One server, many tools** — A single `redhands` binary covers all offensive security tooling (like GitHub covers all of GitHub's API surface in one server)
2. **Toolsets for filtering** — Tools grouped by domain; users enable only what they need via `--toolsets` or env vars
3. **Auth lives outside** — MCP hosts (Claude Code, Cursor, VS Code) manage credentials; RedHands accepts config via env vars, not custom RBAC
4. **Stdio first, HTTP second** — Local stdio for development/single-user; HTTP/SSE for remote/team deployment
5. **Observability built-in** — Every tool call is audit-logged; metrics and tracing are first-class
6. **Safe by default** — Allowlisted binaries, input validation, output caps, read-only mode available

---

## Target Users

| User | Use Case |
|------|----------|
| Pentest teams | AI-assisted recon, scanning, vuln assessment via Claude/Cursor |
| Security engineers | Automated security workflows triggered by AI agents |
| Red team operators | AI-augmented offensive operations with full audit trail |
| DevSecOps | Integrate security scanning into AI-powered CI/CD pipelines |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  MCP Host (Claude Code / Cursor / VS Code)              │
│  - Manages sessions                                      │
│  - Controls tool approval                                │
│  - Passes credentials via env vars                       │
└──────────────┬──────────────────────────────────────────┘
               │ stdio (local) or HTTP/SSE (remote, future)
               ▼
┌─────────────────────────────────────────────────────────┐
│  RedHands MCP Server                                     │
│                                                          │
│  ┌──────────────┐  ┌──────────┐  ┌────────────┐        │
│  │  Middleware   │  │ Executor │  │ Audit Log  │        │
│  │              │  │          │  │            │        │
│  │ • ratelimit  │  │ allowlist │  │ JSONL file │        │
│  │ • cache      │  │ sandbox   │  │            │        │
│  │ • audit      │  │ timeout   │  │            │        │
│  └──────┬───────┘  └─────┬────┘  └────────────┘        │
│         │                 │                              │
│         └────────┬────────┘                              │
│                  ▼                                        │
│  ┌──────────────────────────────────────────────┐       │
│  │  Toolsets (category-based layout)             │       │
│  │                                               │       │
│  │  tools/scan/     nmap, masscan, rustscan      │       │
│  │  tools/recon/    subfinder, amass, dns,       │       │
│  │                  wayback, gau, arjun           │       │
│  │  tools/web/      httpx, katana, nikto,        │       │
│  │                  whatweb, testssl              │       │
│  │  tools/fuzz/     ffuf, gobuster, feroxbuster  │       │
│  │  tools/exploit/  sqlmap                       │       │
│  │  tools/vuln/     nuclei                       │       │
│  │  tools/system/   health                       │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### Directory Layout

```
tools/
├── scan/            Port scanning
│   ├── nmap/        TCP/UDP scan, service detect, OS fingerprint, vuln scan
│   ├── masscan/     Internet-scale port scanning (10M pps)
│   └── rustscan/    Modern fast port scanner
├── recon/           Reconnaissance & enumeration
│   ├── subfinder/   Subdomain enumeration
│   ├── amass/       ASN and network mapping
│   ├── dns/         DNS lookups via dig
│   ├── wayback/     Wayback Machine URL retrieval
│   ├── gau/         URL fetching from multiple sources
│   └── arjun/       HTTP parameter discovery
├── web/             Web analysis & probing
│   ├── httpx/       HTTP service probing
│   ├── katana/      Web crawling (JS, headless)
│   ├── nikto/       Web server vulnerability scanning
│   ├── whatweb/     Web technology fingerprinting
│   └── testssl/     TLS/SSL encryption testing
├── fuzz/            Fuzzing & brute-forcing
│   ├── ffuf/        Web fuzzing (dirs, params, vhosts)
│   ├── gobuster/    Directory/file brute-forcing
│   └── feroxbuster/ Recursive content discovery
├── exploit/         Exploitation
│   └── sqlmap/      SQL injection detection & exploitation
├── vuln/            Vulnerability scanning
│   └── nuclei/      Template-based vulnerability scanning
└── system/          Internal
    └── health/      Server health check & dependency status
```

---

## Toolsets & Tools

### Toolset: `nmap` — Nmap Suite

| Tool | Binary | Description |
|------|--------|-------------|
| `nmap_port_scan` | nmap | TCP/UDP port scanning (SYN, connect, UDP) |
| `nmap_service_detect` | nmap | Service and version detection (-sV) |
| `nmap_os_detect` | nmap | OS fingerprinting (-O) |
| `nmap_vuln_scan` | nmap | NSE vulnerability scripts |

### Toolset: `scan` — Port Scanning

| Tool | Binary | Description |
|------|--------|-------------|
| `masscan_scan` | masscan | Internet-scale port scanning (10M pps) |
| `rustscan_scan` | rustscan | Modern fast port scanner (all 65535 ports) |

### Toolset: `recon` — Reconnaissance & Enumeration

| Tool | Binary | Description |
|------|--------|-------------|
| `subfinder_enum` | subfinder | Passive subdomain enumeration |
| `amass_enum` | amass | Network mapping and ASN discovery |
| `dns_lookup` | dig | DNS record queries (A, AAAA, MX, NS, TXT, etc.) |
| `waybackurls` | waybackurls | Fetch archived URLs from the Wayback Machine |
| `gau_urls` | gau | Fetch URLs from AlienVault OTX, Wayback, CommonCrawl, URLScan |
| `arjun_discover` | arjun | HTTP parameter discovery (hidden GET/POST params) |

### Toolset: `web` — Web Analysis & Probing

| Tool | Binary | Description |
|------|--------|-------------|
| `httpx_probe` | httpx | HTTP service probing with tech detection |
| `katana_crawl` | katana | Next-gen web crawler (JS crawling, headless) |
| `nikto_scan` | nikto | Web server vulnerability scanner |
| `whatweb_fingerprint` | whatweb | Web technology fingerprinting |
| `testssl_scan` | testssl.sh | TLS/SSL encryption testing |

### Toolset: `fuzz` — Fuzzing & Brute-forcing

| Tool | Binary | Description |
|------|--------|-------------|
| `ffuf_fuzz` | ffuf | Web fuzzing (dirs, params, vhosts) |
| `gobuster_dir` | gobuster | Directory/file brute-forcing |
| `feroxbuster_scan` | feroxbuster | Recursive content discovery (forced browsing) |

### Toolset: `exploit` — Exploitation

| Tool | Binary | Description |
|------|--------|-------------|
| `sqlmap_scan` | sqlmap | Automatic SQL injection detection and exploitation |

### Toolset: `vuln` — Vulnerability Scanning

| Tool | Binary | Description |
|------|--------|-------------|
| `nuclei_scan` | nuclei | Template-based vulnerability scanning |

### System (always enabled)

| Tool | Binary | Description |
|------|--------|-------------|
| `redhands_health` | — | Server health check and binary dependency status |

### Default Toolsets

When `REDHANDS_TOOLSETS` is unset: all toolsets are enabled.

### Configuration

```bash
# Enable specific toolsets
export REDHANDS_TOOLSETS=nmap,recon,web

# Enable all scanning + exploitation
export REDHANDS_TOOLSETS=nmap,recon,web,fuzz,scan,exploit,vuln

# All tools (default when unset)
export REDHANDS_TOOLSETS=
```

---

## Release History

### v0.1.0 — Foundation (shipped)

- MCP protocol core (JSON-RPC 2.0, stdio transport)
- 4 Nmap tools (port_scan, service_detect, os_detect, vuln_scan)
- Secure binary execution with allowlist + sandbox
- Structured audit logging (JSONL)
- Input validation and shell metacharacter rejection

### v0.2.0 — Tool Expansion (shipped)

- Toolset filtering via `REDHANDS_TOOLSETS` env var
- Added 13 tools: subfinder, httpx, nuclei, ffuf, dns, amass, katana, nikto, gobuster, wayback, testssl, whatweb, health
- Token bucket rate limiting middleware
- LRU result cache with TTL
- Binary auto-discovery

### v0.3.0 — Full Suite (shipped, current)

- Added 6 more tools: sqlmap, masscan, rustscan, feroxbuster, arjun, gau
- New toolset categories: scan, exploit
- Category-based directory layout (tools organized by domain)
- 23 tools total across 7 toolsets + system

---

## Release Plan

### v0.4.0 — HTTP/SSE Transport (Next)

**Goal:** Remote access for team use — one server, multiple agents connect.

| Deliverable | Details |
|-------------|---------|
| HTTP transport | `/mcp` endpoint, streamable HTTP per MCP spec |
| SSE fallback | For clients that don't support streamable HTTP |
| Token auth | Bearer token validation (env-configured shared secret) |
| TLS | `--tls-cert` / `--tls-key` flags |
| Health endpoint | `GET /health` for load balancers and monitoring |
| Concurrent sessions | Multiple agents connected simultaneously |

### v0.5.0 — Observability & Deployment

**Goal:** Production-ready deployment with full observability.

| Deliverable | Details |
|-------------|---------|
| OpenTelemetry | OTLP export for traces and metrics |
| Structured logging | slog with JSON output, configurable level |
| Metrics | Tool call count, duration histogram, error rate |
| Helm chart | Kubernetes deployment with configurable resources |
| Docker Compose | Local multi-container setup |

### v0.6.0 — Advanced Features

**Goal:** Workflow support and expanded tool coverage.

| Deliverable | Details |
|-------------|---------|
| Workflow hints | Tool descriptions that guide AI agents to chain tools logically |
| Finding dedup | Cross-tool finding deduplication |
| Additional tools | Expand coverage per user demand |

---

## Non-Goals (Explicit)

| Not building | Reason |
|--------------|--------|
| Custom RBAC/permissions | MCP hosts control tool approval; adding our own layer adds friction without value |
| Multi-tenancy in the server | Deploy separate instances per team; simpler, more isolated |
| Web UI / dashboard | The AI agent IS the UI; audit logs feed into existing SIEM/Grafana |
| Custom auth protocol | Industry pattern is env-var tokens; no reason to diverge |
| Database persistence | Audit logs go to files/OTLP; findings returned to the agent directly |

---

## Security Model

```
┌─────────────────────────────────────────────┐
│ Layer 1: MCP Host (Claude Code)             │
│ • Human-in-the-loop tool approval           │
│ • Session isolation                         │
│ • Credential injection via env              │
├─────────────────────────────────────────────┤
│ Layer 2: RedHands Server                    │
│ • Binary allowlist (only known tools)       │
│ • Argument injection prevention             │
│ • Target validation (IP/CIDR/hostname)      │
│ • Output size caps (10MB default)           │
│ • Execution timeout (5min default)          │
│ • Read-only mode                            │
│ • Rate limiting (token bucket)               │
├─────────────────────────────────────────────┤
│ Layer 3: OS / Container                     │
│ • Non-root execution                        │
│ • Pdeathsig (Linux)                         │
│ • Network policy (K8s, v0.4+)              │
│ • Minimal container image                   │
├─────────────────────────────────────────────┤
│ Layer 4: Audit Trail                        │
│ • Every tool call logged                    │
│ • Params sanitized (secrets redacted)       │
│ • OTLP export (v0.4+)                      │
│ • Immutable append-only log                 │
└─────────────────────────────────────────────┘
```

---

## Configuration Reference

All configuration via environment variables (`REDHANDS_*` prefix):

| Variable | Default | Description |
|----------|---------|-------------|
| `REDHANDS_TOOLSETS` | (all) | Comma-separated toolsets to enable (nmap,recon,web,fuzz,scan,exploit,vuln) |
| `REDHANDS_TIMEOUT` | `5m` | Execution timeout per tool call |
| `REDHANDS_MAX_OUTPUT` | `10485760` | Max output bytes per execution (10MB) |
| `REDHANDS_RATE_LIMIT` | `10` | Token bucket refill rate (requests/sec) |
| `REDHANDS_RATE_BURST` | `20` | Token bucket burst capacity |
| `REDHANDS_CACHE_TTL` | `5m` | Result cache TTL |
| `REDHANDS_CACHE_SIZE` | `100` | Max cached results (LRU eviction) |
| `REDHANDS_AUDIT_FILE` | `audit.jsonl` | Audit log file path |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Tool call latency (overhead) | <50ms added beyond tool execution time |
| Concurrent scans supported | 10+ simultaneous without degradation |
| Binary startup time | <100ms to first `tools/list` response |
| Test coverage | >80% on pkg/ packages |
| Supported tools | 23 shipped (v0.3.0), expanding |
| Container image size | <100MB with tools installed |

---

## Competitive Landscape

| Project | Scope | Difference from RedHands |
|---------|-------|--------------------------|
| GitHub MCP Server | GitHub API | Different domain; same architecture pattern |
| mcp-atlassian | Jira/Confluence | Different domain; Python, similar patterns |
| PentestGPT | AI pentesting | Monolithic, no MCP, not composable |
| HackerGPT | AI security chat | Chat-only, no tool protocol |
| RedHands | Security tool MCP | Standardized MCP protocol, composable with any AI agent |

RedHands is the first production-grade MCP server purpose-built for offensive security tooling.
