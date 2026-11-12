# Dependency maintenance and releases

`scripts/dependencies.json` is the shared reviewed manifest for Docker, Linux/macOS,
and Windows installers. It pins Go tool versions, top-level Python package versions,
the Nikto source commit, and SHA-256 digests for supported release binaries.

`scripts/dependencies.py` validates the manifest, verifies downloads before installation,
and extracts only the expected executable into a private temporary directory. A missing
platform artifact or checksum mismatch fails closed. No upstream install script is
downloaded and executed as root. Existing installed tools are not overwritten by the
interactive profile installer merely to match the lock.

```sh
python3 scripts/dependencies.py validate
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/dependencies.py install chisel --output /path/to/bin
```

## Updating the lock

1. Review the upstream release and license/compatibility changes.
2. Pin the exact Go module version, Python distribution version, or source commit.
3. For artifacts, compare SHA-256 against the publisher's release checksums/signatures
   when available and GitHub's asset digest. Go toolchain hashes come from `go.dev/dl/`.
4. Download and verify the artifact without executing it, then test in an isolated lab.
5. Update the manifest and run installer tests, application tests and Docker CI.

The initial binary digests were taken from upstream GitHub release metadata and Go's
published download metadata. This is trust-on-review: pinning detects later changes,
but is not an independent publisher signature or a guarantee a binary is benign.
Go installs retain Go's normal module checksum database verification.
CI and release builds read their Go version from `go.mod` with `check-latest: true`,
so setup-go does not silently reuse an older cached patch. Docker's Go stages and
the downloaded toolchain are pinned to the same patched 1.26.11 baseline. This fixes
GO-2026-6859 (CVE-2026-97054), which affects Go 1.26.10 and earlier and Go 1.27 before
1.27.4. Keep vulnerability scanning enabled when updating any toolchain.
The application itself still uses only Go's standard library; passphrase derivation
uses its PBKDF2 implementation rather than adding a cryptography dependency.

## Container image contents

The Docker image installs every release binary in `scripts/dependencies.json`
through the verified installer, including the KubeDagger server (C2 server for
lab use) and the Barzakh server (REST scanner API). All three KubeDagger
binaries (client, operator, server) are pinned to the same **v0.5.0** release,
and all three Barzakh binaries (adversary, scanner, server) to **v0.7.0**.

The StaticZero and Aegis-Shadow defense engines also ship as verified release
assets (Linux only, eBPF objects embedded): `staticzero-defense`,
`modem-firmware`, and `sdr-bridge` (StaticZero v0.5.0) and
`aegis-shadow-defense` (Aegis-Shadow v0.1.1) are installed into the image.
The research **offense** binaries (`staticzero-offense`,
`aegis-shadow-offense`) are deliberately **not** bundled: no RedHands tool
executes them, and they belong in an isolated lab VM only. To use one with the
container, download it from the matching release (checksum-verified via the
`telecom` install profile on a host, or manually) and bind-mount it
individually into `/usr/local/bin` (already on `PATH`; per-file mounts do not
shadow the tools the image installed there):

```yaml
volumes:
  - ./local-bin/staticzero-offense:/usr/local/bin/staticzero-offense:ro
```

The binary allowlist resolves tools by name on `PATH` at startup, so mounted
binaries are discovered automatically; a missing binary is reported as missing
rather than replaced with an unverified download. Any other server binary that
is not published in a reviewed release must be provided the same way.

## Known gaps

- Distribution packages and container base tags still receive upstream updates.
- Python transitive dependencies are not yet a complete hash-locked wheel set.
- Certipy is pinned to 4.8.2 for Debian bookworm's Python 3.11; 5.x requires Python
  3.12+. Changing this pin requires testing both runtime and command compatibility.
- RustScan/testssl.sh lack a reviewed artifact here and require manual installation.
- CrackMapExec is no longer present on PyPI; a replacement must be reviewed for CLI
  compatibility before changing the existing wrapper.
- KubeDagger client has no Windows/macOS release in the pinned release. The installer
  reports that instead of fetching a nonexistent URL.
- Docker native architecture builds no longer download amd64-only Go. Multi-platform
  runtime image validation is still needed, especially external binary compatibility.

## Application releases

The tag-triggered release workflow builds server, CLI and offline credential-maintenance
utilities for Linux/macOS/Windows on amd64/arm64, embeds the shared version, generates
`SHA256SUMS`, and publishes GitHub build-provenance attestations. It runs only after a
version tag is pushed; adding this workflow does not publish a release by itself.
The application and health reports share `pkg/version.Version`, overridden at release build time.

The quick installer requires checksums for release downloads. Older archives without
`SHA256SUMS` are intentionally rejected; use a reviewed source build instead. Verification
against release checksums is not signature verification: users can additionally verify
GitHub's build-provenance attestations with the GitHub CLI before installation.

CI runs application vulnerability analysis, cross-platform client/transport tests, and
dependency-installer tests. Docker CI includes a non-root, real-Nmap TCP-connect smoke
test against one local listening port plus Certipy/Impacket help-entry-point checks
with `--network none`. Broad compatibility tests should run
only in isolated environments; they must never target third-party systems.
