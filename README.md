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
cmd/redhands/            Entry point, tool registration, config
pkg/
├── mcp/                 MCP protocol (JSON-RPC 2.0, stdio transport)
├── executor/            Secure binary execution + sandbox
├── audit/               Structured audit logging (JSONL)
├── config/              Environment-based configuration
├── cache/               LRU result cache with TTL
├── ratelimit/           Token bucket rate limiter
└── nmap/                Nmap XML parser + query helpers
tools/
├── scan/                Port scanning
│   ├── nmap/            TCP/UDP port scan, service detect, OS fingerprint, vuln scan
│   ├── masscan/         Internet-scale port scanning (10M pps)
│   └── rustscan/        Modern fast port scanner
├── recon/               Reconnaissance & enumeration
│   ├── subfinder/       Subdomain enumeration
│   ├── amass/           ASN and network mapping
│   ├── dns/             DNS lookups via dig
│   ├── wayback/         Wayback Machine URL retrieval
│   ├── gau/             URL fetching from multiple sources
│   └── arjun/           HTTP parameter discovery
├── web/                 Web analysis & probing
│   ├── httpx/           HTTP service probing
│   ├── katana/          Web crawling (JS, headless)
│   ├── nikto/           Web server vulnerability scanning
│   ├── whatweb/         Web technology fingerprinting
│   └── testssl/         TLS/SSL encryption testing
├── fuzz/                Fuzzing & brute-forcing
│   ├── ffuf/            Web fuzzing (dirs, params, vhosts)
│   ├── gobuster/        Directory/file brute-forcing
│   └── feroxbuster/     Recursive content discovery
├── exploit/             Exploitation
│   └── sqlmap/          SQL injection detection & exploitation
├── vuln/                Vulnerability scanning
│   └── nuclei/          Template-based vulnerability scanning
└── system/              Internal
    └── health/          Server health check & dependency status
```

## License

MIT
