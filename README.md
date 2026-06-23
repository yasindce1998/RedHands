# RedHands

[![CI](https://github.com/yasindce1998/redhands/actions/workflows/ci.yml/badge.svg)](https://github.com/yasindce1998/redhands/actions/workflows/ci.yml)

Enterprise-grade MCP server that exposes offensive security tools to AI agents. Built in Go with toolset grouping, rate limiting, result caching, and structured audit logging.

```
go install github.com/yasindce1998/redhands/cmd/redhands@latest
```

## Quick Start

```bash
# Build
make build

# Run with Claude Code / Cursor / VS Code
# Add to your MCP config:
{
  "mcpServers": {
    "redhands": {
      "command": "/path/to/redhands"
    }
  }
}
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

### System

| Tool | Description |
|------|-------------|
| `redhands_health` | Server health check and binary dependency status |

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDHANDS_TOOLSETS` | (all) | Comma-separated toolsets to enable (e.g., `nmap,recon,web,scan,exploit`) |
| `REDHANDS_TIMEOUT` | `5m` | Execution timeout per tool call |
| `REDHANDS_MAX_OUTPUT` | `10485760` | Max output bytes per execution (10MB) |
| `REDHANDS_RATE_LIMIT` | `10` | Token bucket refill rate (requests/sec) |
| `REDHANDS_RATE_BURST` | `20` | Token bucket burst capacity |
| `REDHANDS_CACHE_TTL` | `5m` | Result cache TTL |
| `REDHANDS_CACHE_SIZE` | `100` | Max cached results (LRU eviction) |
| `REDHANDS_AUDIT_FILE` | `audit.jsonl` | Audit log file path |

### Toolset Filtering

Enable only specific toolsets:

```bash
# Only Nmap and recon tools
export REDHANDS_TOOLSETS=nmap,recon

# Enable exploitation tools
export REDHANDS_TOOLSETS=nmap,recon,web,fuzz,scan,exploit,vuln

# All tools (default when unset)
export REDHANDS_TOOLSETS=
```

## Security

- **Binary allowlist** — only known security tools can be executed
- **Shell metacharacter rejection** on all inputs
- **Target validation** — strict format checks for IPs, domains, URLs
- **Output size cap** — 10MB per execution
- **Execution timeout** — 5 minutes per tool call
- **Rate limiting** — token bucket prevents abuse
- **Full audit trail** — every tool invocation logged as JSONL

## Development

```bash
make build      # Build binary to bin/
make test       # Run tests with race detector
make lint       # Run golangci-lint
```

## Docker

```bash
docker build -t redhands .
docker run -i redhands
```

## Architecture

```
cmd/redhands/       Entry point, tool registration, config
pkg/mcp/            MCP protocol (JSON-RPC 2.0, stdio transport)
pkg/executor/       Secure binary execution + sandbox
pkg/audit/          Structured audit logging (JSONL)
pkg/config/         Environment-based configuration
pkg/cache/          LRU result cache with TTL
pkg/ratelimit/      Token bucket rate limiter
pkg/nmap/           Nmap XML parser + query helpers
tools/nmap/         Nmap MCP tools (port scan, service, OS, vuln)
tools/subfinder/    Subdomain enumeration
tools/amass/        ASN and network mapping
tools/dns/          DNS lookups via dig
tools/httpx/        HTTP probing
tools/katana/       Web crawling
tools/nikto/        Web server scanning
tools/ffuf/         Web fuzzing
tools/gobuster/     Directory brute-forcing
tools/nuclei/       Template-based vuln scanning
tools/testssl/      TLS/SSL testing
tools/whatweb/      Web fingerprinting
tools/wayback/      Wayback Machine URL retrieval
tools/gau/          URL fetching from multiple sources
tools/arjun/        HTTP parameter discovery
tools/masscan/      Internet-scale port scanning
tools/rustscan/     Modern fast port scanner
tools/feroxbuster/  Recursive content discovery
tools/sqlmap/       SQL injection testing
tools/health/       Server health check
```

## License

MIT
