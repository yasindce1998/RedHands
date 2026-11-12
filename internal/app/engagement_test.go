package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestCampaignEngagementBindingEndToEnd(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	srv.RegisterTool(&jsonTool{name: "fake_scan", text: "scan done"})

	mgr := engagement.NewManager(t.TempDir())
	lab, err := mgr.Create("lab-1", "test-client", []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	prod, err := mgr.Create("prod-2", "other-client", []string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	// Creating lab-1 first made it active; switch to prod-2 (by ID).
	if err := mgr.Switch(prod.ID); err != nil {
		t.Fatalf("switch engagement: %v", err)
	}
	_ = lab

	cfg := &config.Config{WorkflowStateDir: t.TempDir(), WorkflowTemplateDir: t.TempDir(), WorkflowMaxParallel: 2}
	SetupCampaign(srv, cfg, nil, mgr)

	run := func(params string) string {
		return string(srv.HandleRaw(json.RawMessage(
			`{"jsonrpc":"2.0","id":1,"method":"campaign/run","params":` + params + `}`)))
	}

	// Binding to the active engagement succeeds.
	resp := run(`{"engagement":"prod-2","steps":[{"tool":"fake_scan"}]}`)
	if !strings.Contains(resp, `"success":true`) {
		t.Fatalf("bound campaign failed: %s", resp)
	}

	// Binding to a non-active engagement fails before any step runs.
	resp = run(`{"engagement":"lab-1","steps":[{"tool":"fake_scan"}]}`)
	if !strings.Contains(resp, "not the active engagement") {
		t.Fatalf("expected inactive-engagement rejection: %s", resp)
	}

	// Binding to an unknown engagement fails with a creation hint.
	resp = run(`{"engagement":"ghost","steps":[{"tool":"fake_scan"}]}`)
	if !strings.Contains(resp, "engagement_create") {
		t.Fatalf("expected not-found rejection: %s", resp)
	}

	// Unbound campaigns still run.
	resp = run(`{"steps":[{"tool":"fake_scan"}]}`)
	if !strings.Contains(resp, `"success":true`) {
		t.Fatalf("unbound campaign failed: %s", resp)
	}
}
