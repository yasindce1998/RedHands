# Evidence and loot recovery

## Layout and compatibility

New evidence artifacts are direct children of `REDHANDS_EVIDENCE_DIR`, named
`<random-id>.<extension>`. Their original tool/host labels are in `index.json`, not
filenames. The versioned index stores relative filenames, timestamps, sizes and SHA-256
checksums, so moving the directory preserves its references. Public tool responses use
absolute paths for the current deployment.

Opening the store checks the index schema, record IDs, paths, file types, size limits
and artifact checksums. A corrupt index or missing/changed indexed file stops startup.
This deliberately replaces the old behavior of forgetting evidence metadata or
silently disabling the evidence store. A checksum is not a digital signature: anyone
who can edit both the index and files can change both.

Older evidence directories have no persistent index. They remain usable for new
captures, but their old files are not automatically indexed, renamed or removed. Keep
them: the application cannot reconstruct reliable tool/host/timestamp metadata from
arbitrary legacy filenames. No automatic legacy import is performed.

Existing well-formed loot arrays and their old IDs remain readable. New IDs are random.
Loot records require a nonempty ID, type, description and timestamp; duplicate IDs,
null records, invalid JSON or oversized files fail opening instead of being discarded.
`loot.json` keeps its existing array format.

## Failure handling

1. Stop the server and all other writers before repairs or moving directories.
2. Make a private copy of the **entire** evidence/loot directory, including unindexed
   files. Do not place an unencrypted backup in a public repository.
3. Read the startup error. For evidence checksum/missing-file errors, restore the
   matching original artifact and index from the same backup. Do not regenerate a
   checksum just to bypass a failed verification.
4. For malformed metadata, repair it offline from a verified backup. The application
   does not automatically replace the invalid file with an empty store.
5. Restart and confirm the expected `evidence_list`, `loot_list` and `loot_search`
   results before retiring backups.

An evidence save commits the private artifact first and then atomically replaces its
index. An ordinary index-write failure removes only the newly created artifact and
keeps the previous state. A crash between these two commits can leave an unindexed
artifact; no automatic orphan cleanup runs, because legacy files and user artifacts
must not be deleted based on absence from the index.

Loot uses one atomic file replacement. An ordinary write failure does not publish the
new record in memory or assign a generated ID to the caller. If replacement succeeded
but directory syncing failed, both stores retain the committed state and return a
durability warning. Inspect the store before manually retrying after any warning;
automatic retries are not performed.

The stores use in-process synchronization, **not multi-process transactions**. Running
multiple servers against the same directories or modifying them while the server is
running is unsupported. Store directories and their parent directories must be trusted.
Rooted filesystem operations reduce traversal/symlink risk but do not defend against
host administrators, bind mounts or an external process modifying live data.

## Screenshots

The screenshot tool receives the application's shared executor. It does not perform
its own PATH lookup or call `os/exec` directly. Operator approval, target scope checks,
execution concurrency, timeout, stdout/stderr caps and process cancellation still apply.
Library callers must supply an executor explicitly; the `Screenshot` method and
`NewEvidenceScreenshotTool` constructor now take one.

Captures use a private temporary directory under the evidence directory. Only a regular
file containing a validated PNG is published. Command failure, cancellation, missing
output, malformed/truncated PNGs, symlinks, oversize captures and failed index writes do
not publish new evidence. Active captures do not hold the metadata lock while the
external command runs. Staging is cleaned on normal returns; an abrupt process crash
can leave a `.screenshot-*` directory for offline review.

Install CutyCapt and its display/headless runtime separately and make it discoverable
before server startup. It is not installed by the default image. URL validation permits
only absolute HTTP(S) URLs without credentials or whitespace. Browser redirects,
subresources, CPU/memory and disk consumption still require external network isolation
and resource quotas. Executor stdout/stderr limits do **not** bound browser file writes.

## Limits and confidentiality

- Evidence: 10,000 items; 16 MiB index; 32 MiB per artifact.
- Screenshot PNGs: additionally limited to 16 megapixels before full decoding.
- Loot: 10,000 items; 32 MiB serialized `loot.json`.
- Evidence startup verification reads every indexed artifact, so startup time grows
  with stored content. These limits do not impose a total directory/disk quota.

New files use private permissions on supported platforms. Existing directories are not
recursively chmodded, and Windows access control must be configured separately.
**Evidence and loot are not encrypted by `REDHANDS_CREDSTORE_KEY`.** Treat originals,
metadata, staging directories, exports and backups as sensitive assessment material.
