// Package e2e contains RedHands' Tier 3 live end-to-end tests: real tool
// executions against safe, test-owned local targets, driven through the
// complete server stack (JSON-RPC dispatch → middleware chain → wrapper →
// BinaryExecutor → real binary → output formatting).
//
// Tier 1 (tools/livecheck) verifies that binaries still accept the argv the
// wrappers build. Tier 2 (testdata golden fixtures) verifies output shapes.
// This suite verifies REAL EXECUTION: an nmap connect scan of a listener the
// test itself owns, a nuclei scan with a test-authored template against a
// local HTTP server, the fully offline barzakh purple-team loop, StaticZero
// doctor/firmware analysis, and a multi-step campaign whose record rules
// persist real binary output into the target database.
//
// The tests live in _test.go files gated behind the `livee2e` build tag, so
// `go test ./...` and the untagged CI jobs never execute them (this file
// exists only so the package always builds). Run the suite with:
//
//	make test-e2e
//	# equivalent: go test -tags=livee2e ./tools/e2e/...
//
// Safety rules for every scenario in this package:
//
//   - The only network targets are 127.0.0.1/localhost listeners or servers
//     the test itself created (net.Listen / httptest.Server).
//   - File inputs and outputs live exclusively in t.TempDir() directories.
//   - Every scenario is deterministic: :0 listeners, fixed seeds for
//     synthetic inputs, bounded polling instead of sleeps.
//   - Every test skips cleanly (never fails) when its binary is missing
//     (exec.LookPath, mirroring tools/livecheck's discovery pattern).
package e2e
