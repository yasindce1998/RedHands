# RedHands — Product Requirements Document

## Overview

RedHands is an MCP (Model Context Protocol) server that exposes offensive security tools to AI agents. It follows the same architecture patterns used by GitHub's MCP server and Atlassian's MCP server — a single-binary Go server that starts with stdio transport, groups tools into logical toolsets, and delegates auth to the MCP host via environment variables.

**Current state:** v0.1.0 shipped with stdio transport, 4 Nmap tools, secure binary execution, and structured audit logging.

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
               │ stdio (local) or HTTP/SSE (remote)
               ▼
┌─────────────────────────────────────────────────────────┐
│  RedHands MCP Server                                     │
│                                                          │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐             │
│  │ Toolsets │  │ Executor │  │ Audit Log  │             │
│  │         │  │          │  │            │             │
│  │ • recon │  │ allowlist │  │ JSONL file │             │
│  │ • scan  │  │ sandbox   │  │ (or OTLP)  │             │
│  │ • vuln  │  │ timeout   │  │            │             │
│  │ • enum  │  │ caps      │  │            │             │
│  └────┬────┘  └─────┬────┘  └────────────┘             │
│       │              │                                   │
│       └──────┬───────┘                                   │
│              ▼                                           │
│  ┌──────────────────────┐                               │
│  │  Binary Execution    │                               │
│  │  nmap, nuclei,       │                               │
│  │  subfinder, httpx... │                               │
│  └──────────────────────┘                               │
└─────────────────────────────────────────────────────────┘
```

---

## Toolsets & Tools

### Toolset: `recon` — Subdomain & Asset Discovery

| Tool | Binary | Description |
|------|--------|-------------|
| `subfinder_enumerate` | subfinder | Passive subdomain enumeration |
| `amass_enum` | amass | Active/passive subdomain enumeration |
| `httpx_probe` | httpx | HTTP probing, tech detection, status codes |

### Toolset: `scan` — Port & Service Scanning (shipped)

| Tool | Binary | Description |
|------|--------|-------------|
| `nmap_port_scan` | nmap | TCP/UDP port scanning |
| `nmap_service_detect` | nmap | Service version detection |
| `nmap_os_detect` | nmap | OS fingerprinting |

### Toolset: `vuln` — Vulnerability Scanning

| Tool | Binary | Description |
|------|--------|-------------|
| `nmap_vuln_scan` | nmap | NSE vulnerability scripts (shipped) |
| `nuclei_scan` | nuclei | Template-based vulnerability scanning |
| `nuclei_scan_custom` | nuclei | Custom template execution |

### Toolset: `enum` — Service Enumeration

| Tool | Binary | Description |
|------|--------|-------------|
| `ffuf_fuzz` | ffuf | Web path/parameter fuzzing |
| `gobuster_dir` | gobuster | Directory brute-forcing |
| `dnsrecon_enum` | dnsrecon | DNS enumeration |

### Toolset: `analyze` — Output Analysis

| Tool | Binary | Description |
|------|--------|-------------|
| `parse_nmap_xml` | — | Parse existing Nmap XML files |
| `parse_nuclei_json` | — | Parse existing Nuclei JSON output |
| `summarize_findings` | — | Aggregate findings across tools |

### Default Toolsets

When no `--toolsets` flag is specified: `scan`, `vuln` (safe starting point).

### Configuration

```bash
# Enable specific toolsets
redhands stdio --toolsets=recon,scan,vuln,enum

# Enable individual tools
redhands stdio --tools=nmap_port_scan,nuclei_scan

# Read-only mode (recon/scan only, no active exploitation)
redhands stdio --read-only

# Via environment variables
REDHANDS_TOOLSETS=recon,scan,vuln
REDHANDS_READ_ONLY=true
```

---

## Release Plan

### v0.2.0 — Tool Expansion (Next)

**Goal:** Add Nuclei and recon tools, implement toolset filtering.

| Deliverable | Details |
|-------------|---------|
| Toolset system | `--toolsets`, `--tools`, `--read-only` flags + env vars |
| Nuclei integration | `nuclei_scan` with template category filtering |
| Subfinder integration | `subfinder_enumerate` with source config |
| httpx integration | `httpx_probe` with tech detection |
| Output parsers | Nuclei JSON parser, subfinder text parser |
| Binary discovery | Auto-detect installed tools, report missing |

**Acceptance criteria:**
- `redhands stdio --toolsets=recon,scan,vuln` starts with tools from all three groups
- `tools/list` only returns tools from enabled toolsets
- Each new tool has input validation matching the Nmap standard
- Missing binaries reported gracefully (tool listed but returns clear error)

---

### v0.3.0 — HTTP/SSE Transport

**Goal:** Remote access for team use — one server, multiple agents connect.

| Deliverable | Details |
|-------------|---------|
| HTTP transport | `/mcp` endpoint, streamable HTTP per MCP spec |
| SSE fallback | For clients that don't support streamable HTTP |
| Token auth | Bearer token validation (env-configured shared secret) |
| TLS | `--tls-cert` / `--tls-key` flags, auto-TLS via Let's Encrypt option |
| Health endpoint | `GET /health` for load balancers and monitoring |
| Concurrent sessions | Multiple agents connected simultaneously |

**Configuration:**
```bash
# Remote mode
redhands http --addr=0.0.0.0:8443 --token=$REDHANDS_TOKEN --tls-cert=cert.pem --tls-key=key.pem

# MCP host config for remote
{
  "mcpServers": {
    "redhands": {
      "type": "http",
      "url": "https://redhands.internal:8443/mcp",
      "headers": {
        "Authorization": "Bearer ${REDHANDS_TOKEN}"
      }
    }
  }
}
```

**Acceptance criteria:**
- Multiple Claude Code sessions connect to one RedHands instance
- Token validation rejects unauthorized requests
- SSE streaming works for long-running scans
- Graceful connection handling (timeouts, reconnects)

---

### v0.4.0 — Observability & Deployment

**Goal:** Production-ready deployment with full observability.

| Deliverable | Details |
|-------------|---------|
| OpenTelemetry | OTLP export for traces and metrics |
| Structured logging | slog with JSON output, configurable level |
| Metrics | Tool call count, duration histogram, error rate, active scans |
| Dockerfile | Multi-stage with all security tools pre-installed |
| Helm chart | Kubernetes deployment with configurable resources |
| Docker Compose | Local multi-container setup (server + tools) |
| Rate limiting | Per-tool concurrency limits (e.g., max 3 Nmap scans) |

**Acceptance criteria:**
- `docker run redhands` starts with all tools available
- Helm chart deploys to K8s with one `helm install`
- Traces appear in Jaeger/Grafana when OTLP endpoint configured
- Rate limiter prevents resource exhaustion from concurrent scans

---

### v0.5.0 — Advanced Tools & Workflows

**Goal:** Broader tool coverage and multi-step workflow support.

| Deliverable | Details |
|-------------|---------|
| ffuf integration | Web fuzzing with wordlist management |
| gobuster integration | Directory/DNS/vhost brute-forcing |
| amass integration | Advanced asset discovery |
| Workflow hints | Tool descriptions that guide AI agents to chain tools logically |
| Result caching | Cache scan results, serve from cache on repeat queries |
| Finding dedup | Cross-tool finding deduplication |

---

## Non-Goals (Explicit)

| Not building | Reason |
|--------------|--------|
| Custom RBAC/permissions | MCP hosts control tool approval; adding our own layer adds friction without value |
| Multi-tenancy in the server | Deploy separate instances per team; simpler, more isolated |
| Web UI / dashboard | The AI agent IS the UI; audit logs feed into existing SIEM/Grafana |
| Exploit execution tools | Out of scope — RedHands is recon/scan/enum, not exploitation |
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
│ • Rate limiting (v0.4+)                     │
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

All configuration via CLI flags with env var equivalents:

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--toolsets` | `REDHANDS_TOOLSETS` | `scan,vuln` | Enabled toolset groups |
| `--tools` | `REDHANDS_TOOLS` | (all in enabled toolsets) | Individual tool filter |
| `--read-only` | `REDHANDS_READ_ONLY` | `false` | Disable destructive/active tools |
| `--timeout` | `REDHANDS_TIMEOUT` | `5m` | Per-tool execution timeout |
| `--max-output` | `REDHANDS_MAX_OUTPUT` | `10MB` | Max captured stdout per exec |
| `--audit-file` | `REDHANDS_AUDIT_FILE` | `./audit.jsonl` | Audit log path |
| `--addr` | `REDHANDS_ADDR` | (stdio mode) | HTTP listen address |
| `--token` | `REDHANDS_TOKEN` | (none) | Bearer token for HTTP mode |
| `--log-level` | `REDHANDS_LOG_LEVEL` | `info` | Log verbosity |
| `--log-format` | `REDHANDS_LOG_FORMAT` | `json` | Log format (json/text) |

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Tool call latency (overhead) | <50ms added beyond tool execution time |
| Concurrent scans supported | 10+ simultaneous without degradation |
| Binary startup time | <100ms to first `tools/list` response |
| Test coverage | >80% on pkg/ packages |
| Supported tools | 15+ by v0.5 |
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
