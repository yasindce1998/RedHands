# SBOM toolset fixtures

Used by the golden pipeline tests in `tools/sbom/sbom_golden_test.go`
(fixture stdout → exit-code handling → markdown fence → severity summary →
campaign record-rule path resolution).

## Provenance

- `syft-dir-sbom.json` — **real run**: `syft v1.57.1` (linux-amd64 release
  binary) against a directory containing only this `go.mod`:

  ```go
  module example.com/vulnapp

  go 1.21

  require (
      golang.org/x/text v0.3.0
      gopkg.in/yaml.v2 v2.2.2
  )
  ```

  Capture command (`-q` suppresses the progress UI; stdout is the SBOM):

  ```bash
  syft dir:/path/to/scan-target -o json -q > syft-dir-sbom.json
  ```

  2 artifacts (`golang.org/x/text`, `gopkg.in/yaml.v2`), offline scan (no
  registry/network needed for `dir:` sources).

- `grype-sbom-scan.json` — **real run**: `grype v0.121.3` (linux-amd64
  release binary) scanning the syft fixture above (after letting grype
  download its vulnerability DB):

  ```bash
  grype sbom:syft-dir-sbom.json -o json > grype-sbom-scan.json
  ```

  8 matches (5 High, 3 Medium) against `golang.org/x/text v0.3.0` and
  `gopkg.in/yaml.v2 v2.2.2`. Note the real shapes the wrappers depend on:
  severities are capitalized (`"High"`, `"Medium"`), `vulnerability.description`
  is populated from the DB metadata, `source.target` is a **string** for
  directory sources, and the top-level keys are exactly
  `matches`/`source`/`distro`/`descriptor` (`ignoredMatches` is `omitempty`).

- `grype-image-scan-presenter-golden.json` — **upstream repo test data**,
  copied verbatim from the grype v0.121.3 tree:
  `grype/presenter/json/testdata/snapshot/TestJsonImgsPresenter.golden`.
  This is the JSON presenter's unit-test golden for an **image** source, kept
  here because the real-run fixture above is a directory scan and the image
  `source.target` shape differs (object with `userInput`, `imageID`,
  `manifestDigest`, `layers`, … while directory sources use a plain string).

- `syft-image-sbom-encoder-golden.json` — **upstream repo test data**,
  copied verbatim from the syft v1.57.1 tree:
  `syft/format/syftjson/testdata/snapshot/TestImageEncoder.golden`. The
  syft-json encoder's unit-test golden for an **image** source (image-shaped
  `source.metadata`), complementing the real directory-scan fixture.

## Exit-code semantics pinned by these fixtures

Verified against the real `grype v0.121.3` binary (and its source,
`cmd/grype/cli/cli.go` → `WithMapExitCode`):

- `grype … --fail-on high` with High-severity matches → **exit 2**, and the
  full JSON report is still written to stdout (`runGrype` appends the
  threshold error but still writes the report before returning).
- `--fail-on critical` with only Medium/High matches → exit 0.
- Any other failure (bad source, DB load failure) → exit 1.

This is inverted relative to `barzakh-scanner` (exit 1 = detection, exit 2 =
incomplete): for grype, **exit 2 is the "findings at/above threshold"
detection signal** and exit 1 is a real error. The `vuln_scan_*` wrappers
treat exit 2 as a result, mirroring `tools/barzakh/scan.go`'s
`runWithDetectionExit`.
