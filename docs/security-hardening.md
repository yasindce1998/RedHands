# Security and deployment notes

## Execution policy

Direct tool calls and every workflow step use the same execution path. Authentication,
audit logging, rate limiting, engagement scope checks and dry-run interception apply
before tool execution. Authentication also protects other RPC methods, including
reports and tool listings.

Caching is intentionally limited to `mitre_lookup` and `risk_score_calculate`, which
are pure functions of their inputs. Cache keys include identity and active engagement.
Scans, database reads, secrets, and mutations are never cached.

## Network access

- stdio is for trusted local clients and uses OS access controls. Use `REDHANDS_AUTH=none`.
- SSE and WebSocket default to loopback. Non-loopback listeners require authentication
  **and TLS**. API keys must be provided in the `X-API-Key` header, never a query string.
- For API-key TLS, set `REDHANDS_TLS_CERT` and `REDHANDS_TLS_KEY`. For mTLS, also set
  `REDHANDS_TLS_CA` and `REDHANDS_AUTH=mtls`. Verified client certificates are required.
- TCP supports local unauthenticated access or mTLS; API-key mode is rejected because
  this protocol has no HTTP authentication headers. The optional dashboard follows
  the same authentication and TLS policy as the main transport.
- Browser requests with a foreign Origin are rejected by the SSE/WebSocket handlers.

Example remote SSE configuration:

```sh
export REDHANDS_TRANSPORT=sse
export REDHANDS_SSE_ADDR=:8443
export REDHANDS_AUTH=apikey
export REDHANDS_API_KEY="$(openssl rand -hex 32)"
export REDHANDS_TLS_CERT=/path/to/server.crt
export REDHANDS_TLS_KEY=/path/to/server.key
redhands
```

Use certificates trusted by your clients. Do not disable client certificate validation.
The server rejects empty/default API keys and invalid transport/limit settings at startup.

## Docker

The default Compose service uses stdio and publishes no network ports:

```sh
docker compose run --rm -i redhands
```

For HTTPS, provide `tls/server.crt`, `tls/server.key`, and `REDHANDS_API_KEY`, then
start **only** the secure service:

```sh
docker compose --profile secure up redhands-secure
```

The published HTTPS port defaults to `127.0.0.1:8443`. Change that binding explicitly
if remote access is needed. Audit logs and assessment databases use separate named
volumes for the local and secure services. The image runs as a non-root user; tools
requiring raw sockets, device access, or other privileges need a separately reviewed
deployment. Do not use `--privileged` as a general workaround.

## Credentials and existing databases

Set a strong, randomly generated `REDHANDS_CREDSTORE_KEY` before storing credentials.
Secrets are kept in `credstore.enc`; the target database contains credential metadata
only. Keep the key backed up separately. Reopening the stores with the same key restores
secrets for credential queries. A wrong key aborts startup.

Existing target databases containing plaintext secrets are rejected without modification.
To migrate, stop the server, make a private offline backup, import each credential into
the encrypted store using its existing credential-store API/tools, and replace the
`secret` values in the JSON database with empty strings. Retain all metadata. Verify
that credentials can be recovered with the key before retiring the backup. Old backups
remain sensitive even after migration. Migration is deliberately not automatic.

Database, credential-store, and engagement updates use private same-directory temporary
files and atomic replacement to avoid partially overwriting the previous file.

## Scope and isolation limitations

When an active engagement has scope entries, explicit targets (including target lists,
URL hosts and CIDRs) are checked. Domain fields used as credential realms are not treated
as extra destinations when a primary target is present. Local firmware/file/process
tools are excluded from network-target checks. With no active/non-empty scope, explicit
target filtering remains unrestricted.

This is **not** a complete network sandbox or a multi-tenant authorization system.
Tool-internal discovery, redirects, DNS rebinding, opaque commands and implicit targets
need operator review and external network restrictions. Engagement switching does not
create isolated databases or per-user permissions. Only trusted operators should have access.

Output is bounded across stdout and stderr together; truncation is reported as an error.
Sequential workflows are limited to 128 steps per request.
On Linux, cancellation kills the tool's process group. These controls are not a full
OS sandbox. Use dedicated environments and only authorized targets.

## Remaining release work

The Dockerfile/tool installers still contain unpinned or unverified third-party downloads.
A complete lock manifest with independently verified checksums, multi-architecture image
builds, and tests against real external binaries remain release requirements. The current
unit/mock integration suite does not validate those external tools. The MCP implementation
still uses the legacy SSE protocol; Streamable HTTP compatibility is separate work.
