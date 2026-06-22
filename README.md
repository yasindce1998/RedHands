# RedHands

[![CI](https://github.com/yasindce1998/redhands/actions/workflows/ci.yml/badge.svg)](https://github.com/yasindce1998/redhands/actions/workflows/ci.yml)

MCP server that exposes offensive security tools to AI agents. Built in Go, follows the same patterns as GitHub's MCP server — single binary, stdio transport, toolset grouping, env-var configuration.

```
go install github.com/yasindce1998/redhands/cmd/redhands@latest
```

## Quick Start

```bash
# Build
make build

# Run with Claude Code
# Add to your MCP config (~/.claude/claude_desktop_config.json):
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
- Nmap installed and on PATH

## Available Tools

| Tool | Description |
|------|-------------|
| `nmap_port_scan` | TCP/UDP port scanning (SYN, connect, UDP) |
| `nmap_service_detect` | Service and version detection (-sV) |
| `nmap_os_detect` | OS fingerprinting (-O) |
| `nmap_vuln_scan` | NSE vulnerability scripts |

## Security

- Binary allowlist — only `nmap` can be executed
- Shell metacharacter rejection on all inputs
- Target validation (IP, CIDR, hostname only)
- Output size cap (10MB)
- Execution timeout (5 minutes)
- Full audit trail (JSONL)

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
cmd/redhands/       Entry point
pkg/mcp/            MCP protocol (JSON-RPC 2.0, stdio)
pkg/executor/       Secure binary execution + sandbox
pkg/audit/          Structured audit logging
pkg/nmap/           Nmap XML parser + query helpers
tools/nmap/         MCP tool implementations
```

## Roadmap

See [docs/prd.md](docs/prd.md) for the full product requirements document.

- **v0.2** — Nuclei, Subfinder, httpx + toolset filtering
- **v0.3** — HTTP/SSE transport for remote/team use
- **v0.4** — OpenTelemetry, Helm chart, rate limiting
- **v0.5** — ffuf, gobuster, workflow hints, result caching

## License

MIT
