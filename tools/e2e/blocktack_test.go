//go:build livee2e

// Real-execution scenarios for the Tier 3 live e2e suite. See doc.go for
// the package design, safety rules, and how to run the suite.
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Scenario 8: BlockTack blockchain adversary simulation. Everything runs
// against local, test-authored artifacts: a synthetic target YAML with a
// loopback endpoint and an unexpired authorization block (the positive
// path), a second target with a non-loopback endpoint (the guardrail
// refusal path — exit 3, rendered as a verdict), plus the read-only
// capabilities and matrix tools. No endpoint is ever contacted: the RPC
// URL points at a port the test never opens and only validate-target
// (dry by construction) runs against the target files.
// ---------------------------------------------------------------------------

// blocktackTargetYAML writes a target file with the given RPC URL and
// authorization expiry.
func blocktackTargetYAML(t *testing.T, rpcURL, expires string) string {
	t.Helper()
	yaml := `apiVersion: blocktack/v1
name: e2e-local
chain:
  type: evm
  network: local
  chainId: 31337
endpoints:
  - name: rpc
    role: rpc
    url: ` + rpcURL + `
contracts: []
components: []
authorization:
  declared: true
  authorizedBy: e2e test
  scope: local fixture validation only
  expires: ` + expires + `
`
	path := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing target YAML: %v", err)
	}
	return path
}

// blocktackRoot resolves the BlockTack installation root from the CLI's
// location: EvalSymlinks first (the installer and dev checkouts put a
// <root>/bin/blocktack — reached through a PATH symlink), then two
// directories up.
func blocktackRoot(t *testing.T) string {
	t.Helper()
	binPath := requireBinary(t, "blocktack")
	if resolved, err := filepath.EvalSymlinks(binPath); err == nil {
		binPath = resolved
	}
	return filepath.Dir(filepath.Dir(binPath))
}

func TestE2E_BlocktackCapabilitiesAndMatrix(t *testing.T) {
	t.Setenv("REDHANDS_BLOCKTACK_ROOT", blocktackRoot(t))
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	out := h.callTool(ctx, t, "blocktack_capabilities", map[string]any{})
	var caps struct {
		Version     string   `json:"version"`
		Commands    []string `json:"commands"`
		Adapters    []string `json:"adapters"`
		NodeModules []string `json:"nodeaudit_modules"`
		Engines     []struct {
			Name    string `json:"name"`
			Present bool   `json:"present"`
		} `json:"engines"`
		Taxonomy struct {
			Weaknesses int `json:"weaknesses"`
		} `json:"taxonomy"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &caps); err != nil {
		t.Fatalf("capabilities JSON does not parse: %v\n%s", err, truncateForTest(out))
	}
	if caps.Version == "" {
		t.Errorf("capabilities carries no version: %s", truncateForTest(out))
	}
	if caps.Taxonomy.Weaknesses < 40 {
		t.Errorf("taxonomy summary reports only %d weaknesses; the release ships 53", caps.Taxonomy.Weaknesses)
	}

	out = h.callTool(ctx, t, "blocktack_matrix", map[string]any{"layer": "L2"})
	var tax struct {
		Layers []struct {
			ID         string `json:"id"`
			Weaknesses []struct {
				ID string `json:"id"`
			} `json:"weaknesses"`
		} `json:"layers"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &tax); err != nil {
		t.Fatalf("matrix layer filter JSON does not parse: %v\n%s", err, truncateForTest(out))
	}
	if len(tax.Layers) != 1 || tax.Layers[0].ID != "L2" || len(tax.Layers[0].Weaknesses) == 0 {
		t.Errorf("layer=L2 filter must return exactly the L2 layer with weaknesses: %s", truncateForTest(out))
	}

	waitFor(t, "audit events for blocktack tools", func() bool {
		calls := h.auditToolCalls(t)
		return calls["blocktack_capabilities"] && calls["blocktack_matrix"]
	})
}

func TestE2E_BlocktackValidateTarget(t *testing.T) {
	t.Setenv("REDHANDS_BLOCKTACK_ROOT", blocktackRoot(t))
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	// Positive path: loopback endpoint + unexpired authorization.
	valid := blocktackTargetYAML(t, "http://127.0.0.1:1", "2099-01-01T00:00:00Z")
	out := h.callTool(ctx, t, "blocktack_validate_target", map[string]any{"target": valid})
	if !strings.Contains(out, "VALID") {
		t.Fatalf("loopback target with authorization must validate:\n%s", truncateForTest(out))
	}
	var verdict struct {
		Valid     bool `json:"valid"`
		Endpoints []struct {
			URL string `json:"url"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(fencedJSON(t, out)), &verdict); err != nil {
		t.Fatalf("verdict JSON does not parse: %v\n%s", err, truncateForTest(out))
	}
	if !verdict.Valid || len(verdict.Endpoints) != 1 || verdict.Endpoints[0].URL != "http://127.0.0.1:1" {
		t.Errorf("unexpected verdict: %s", truncateForTest(out))
	}

	// Guardrail path: a non-loopback endpoint that is not in
	// authorization.liveTargets is refused with exit 3, which the wrapper
	// renders as the verdict (a hard stop, not an operational error).
	remote := blocktackTargetYAML(t, "http://blocktack-e2e.invalid:8545", "2099-01-01T00:00:00Z")
	out = h.callTool(ctx, t, "blocktack_validate_target", map[string]any{"target": remote})
	if !strings.Contains(out, "INVALID") || !strings.Contains(out, "unsafe_endpoint") {
		t.Fatalf("non-loopback endpoint must produce an unsafe_endpoint refusal verdict:\n%s", truncateForTest(out))
	}

	// Expired authorization is likewise a hard stop.
	expired := blocktackTargetYAML(t, "http://127.0.0.1:1", "2000-01-01T00:00:00Z")
	out = h.callTool(ctx, t, "blocktack_validate_target", map[string]any{"target": expired})
	if !strings.Contains(out, "INVALID") {
		t.Fatalf("expired authorization must invalidate the target:\n%s", truncateForTest(out))
	}

	waitFor(t, "audit event for blocktack_validate_target", func() bool {
		return h.auditToolCalls(t)["blocktack_validate_target"]
	})
}

func TestE2E_BlocktackEngineCallLoopbackOnly(t *testing.T) {
	requireBinary(t, "blocktack-evm")
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), scenarioTimeout)
	defer cancel()

	// The wrapper must refuse non-loopback engine RPC URLs before any
	// subprocess runs (engines bypass BlockTack's own guardrails).
	text, isErr := h.callToolRaw(ctx, t, "blocktack_engine_call", map[string]any{
		"engine": "blocktack-evm", "action": "fingerprint", "rpc_url": "http://blocktack-e2e.invalid:8545",
	})
	if !isErr {
		t.Fatalf("engine call against a non-loopback RPC must be refused by the wrapper")
	}
	if !strings.Contains(text, "loopback") {
		t.Errorf("refusal must explain the loopback contract:\n%s", text)
	}
}
