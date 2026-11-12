# Security and deployment notes

## Execution policy

Direct tool calls and every workflow step use the same execution path. Authentication,
audit logging, rate limiting, engagement scope checks and dry-run interception apply
before tool execution. Authentication also protects other RPC methods, including
reports and tool listings.

Caching is intentionally limited to `mitre_lookup` and `risk_score_calculate`, which
are pure functions of their inputs. Cache keys include identity and active engagement.
Scans, database reads, secrets, and mutations are never cached.

`tools/list` includes `x-redhands-policy` and MCP safety annotations. Policies are
server-owned and reset to conservative defaults when a tool is replaced. Mixed-mode
wrappers and unclassified tools/plugins require operator approval. Approve exact names
using `REDHANDS_APPROVED_TOOLS=tool_one,tool_two` only after reviewing all supported modes;
model-provided `approved` fields and wildcard approval do not bypass this check.
Read-only/network/privilege/retry fields describe capabilities; they do not grant OS
privileges or implement a network sandbox. No tool call is automatically retried.

Execution is bounded to `REDHANDS_MAX_CONCURRENT` active calls (default 4) and
`REDHANDS_MAX_QUEUED` waiting calls (default 16) across the server. Queue overflow fails
before execution. `REDHANDS_TIMEOUT` includes queue wait and execution;
`REDHANDS_WORKFLOW_TIMEOUT` bounds the complete workflow (default 30m). Tools must honor
context cancellation; external commands use process cancellation. This is not a durable
background-job system.

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
For new deployments, use `export REDHANDS_CREDSTORE_KEY="hex:$(openssl rand -hex 32)"`.
`hex:` keys must encode exactly 32 random bytes. Human passphrases use PBKDF2-HMAC-SHA256
with a random 16-byte salt and 600,000 iterations. New files have a versioned envelope
and AES-GCM encryption. Legacy SHA-256-derived stores remain readable; opening them
does not rewrite them, while explicit upgrades and subsequent writes use the new format.
Secrets are kept in `credstore.enc`; the target database contains credential metadata
only. Keep the key backed up separately. Reopening the stores with the same key restores
secrets for credential queries. A wrong key aborts startup.

Existing target databases containing plaintext secrets are rejected without modification.
Stop the server and make a private offline backup before any maintenance. The
`redhands-creds` utility reads paths/keys from environment variables, never command-line
secrets, and supports:

```sh
redhands-creds migrate-targetdb # Verify encrypted copies, then clear JSON secrets
redhands-creds verify           # Reopen/decrypt without printing secrets
redhands-creds upgrade          # Upgrade a legacy encrypted file explicitly
# Set REDHANDS_CREDSTORE_NEW_KEY separately before rotation
redhands-creds rotate
```

Migration preserves unknown metadata fields and leaves the source JSON untouched if
verification fails. Stop all writers: it is an offline tool, not a multi-process
transaction. Keep the old backup and key until the migrated/rotated store has been
verified independently. Old backups remain sensitive even after migration. Update the
server's key after rotation. Migration is deliberately not automatic at server startup.

Database, credential-store, and engagement updates use private same-directory temporary
files and atomic replacement to avoid partially overwriting the previous file.

## Evidence and loot storage

- Evidence artifacts and metadata now survive restarts. A versioned `index.json` stores
  relative filenames, tool/host/timestamp metadata, size and SHA-256. Opening the store
  verifies every indexed artifact; missing, modified, symlinked or invalid records fail
  startup. The checksum is an integrity check, not a signature or tamper-proof audit log.
- Artifact names are random IDs with validated extensions, never user-supplied host or
  tool strings. Filesystem reads/writes use Go's rooted filesystem operations, private
  temporary files, and atomic replacement. Store directories must be trusted and owned
  by the server; this is not protection against a hostile administrator or bind mounts.
- Evidence files from older versions have no saved metadata. They remain untouched and
  unlisted; do not delete them simply because the index does not mention them. A crash
  between committing an artifact and its index can also leave an unindexed file. No
  automatic orphan deletion is performed. Back up index and artifacts together.
- Evidence is limited to 10,000 indexed items, a 16 MiB index, and 32 MiB per artifact.
  Verification scans indexed contents at startup, so startup time grows with stored data.
  Loot is limited to 10,000 items and a 32 MiB `loot.json` file. Loot parsing, duplicate
  IDs, null records and missing required fields are validated at load, not merely logged.
- Failed writes do not publish new in-memory records. If replacement committed but
  directory syncing fails, memory retains the committed value and the caller receives
  a durability warning. A returned error does not always mean nothing was committed;
  inspect the store before manually retrying. There are no automatic retries.
- Screenshots use the same allowlisted executor, timeout, process cancellation and
  stdout/stderr bounds as other external tools. Captures are staged privately and only
  valid PNG files (up to 32 MiB / 16 megapixels) are indexed. Missing output, symlinks,
  failed commands and cancellation do not publish artifacts. Captures do not hold the
  metadata lock while the external tool runs.
- Screenshots require `cutycapt` plus a suitable display/headless runtime, installed and
  discoverable at startup. The default image does not bundle it. Only HTTP(S) URLs
  without embedded credentials are accepted. Initial target scope checks still apply;
  redirects, subresources and browser disk usage require external isolation and quotas.

These are single-process stores, not transactional multi-process databases. Loot content
and evidence are **not encrypted** by `REDHANDS_CREDSTORE_KEY`; treat them and their backups
as sensitive assessment data. Valid legacy loot arrays/IDs remain supported; malformed
legacy records must be repaired from a private backup rather than silently discarded.

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
Sequential workflows are limited to 128 steps and 16 MiB aggregate text output per request.
Expanded parameters are bounded to 10 MiB, including repeated output substitutions.
On Linux, cancellation kills the tool's process group. These controls are not a full
OS sandbox. Use dedicated environments and only authorized targets.

## Unsupported configuration and remaining work

The multi-stage campaign engine (`campaign/run`, `status`, `list`, `resume`, `cancel`,
`templates`) is wired into startup. `REDHANDS_WORKFLOW_STATE_DIR`,
`REDHANDS_WORKFLOW_TEMPLATES_DIR`, and `REDHANDS_WORKFLOW_MAX_PARALLEL` are functional.
The environment settings that are rejected as unsupported at startup (a configuration
error rather than silent acceptance) are `REDHANDS_OPSEC_PROXIES`, `REDHANDS_OPERATOR_ID`,
`REDHANDS_SYNC_PEERS`, `REDHANDS_WEBHOOK_URLS`, and `REDHANDS_WEBHOOK_EVENTS`. Remaining
unsupported work: proxy profiles, multi-operator sync, webhook notifications, and the
Streamable HTTP transport. Do not assume the underlying library prototypes for those
features are production features.

See [dependency maintenance](dependencies.md) for lock/checksum coverage and its limits.
Engagement data isolation, durable job scheduling, complete real-binary compatibility
coverage, and Streamable HTTP remain separate work. The SSE client/server path is the
existing legacy implementation; it does not claim modern MCP transport support.
