package registry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/execution"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestRegistryPoliciesAndSafeDefaults(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	cfg := config.Load()
	cfg.Toolsets = []string{"nmap", "intelligence", "wireless"}
	RegisterAll(srv, &Deps{Cfg: &cfg, Exec: executor.NewMock()})
	for _, name := range []string{"nmap_port_scan", "redhands_health", "mitre_lookup"} {
		if srv.ToolPolicy(name).RequiresApproval {
			t.Errorf("unexpected approval for %s", name)
		}
	}
	for _, name := range []string{"wireless_deauth", "wireless_bettercap", "unregistered"} {
		if !srv.ToolPolicy(name).RequiresApproval {
			t.Errorf("unsafe default for %s", name)
		}
	}
	if !srv.ToolPolicy("mitre_lookup").Cacheable || srv.ToolPolicy("nmap_port_scan").Cacheable {
		t.Fatal("wrong cache policy")
	}
	srv.Use(execution.Approval(nil))
	r, err := srv.ExecuteTool(context.Background(), "wireless_deauth", json.RawMessage(`{"interface":"wlan0","target":"test"}`))
	if err != nil || !r.IsError {
		t.Fatalf("approval not enforced: %+v %v", r, err)
	}
	response := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	var decoded struct {
		Result mcp.ToolsListResult `json:"result"`
	}
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, tool := range decoded.Result.Tools {
		if tool.Name == "wireless_deauth" && !tool.Policy.RequiresApproval {
			t.Fatal("policy not published")
		}
	}
	// Replacing a tool, including a previously pure one, clears trusted policy.
	tool, _ := srv.GetTool("mitre_lookup")
	_ = srv.RegisterTool(tool)
	if srv.ToolPolicy("mitre_lookup").Cacheable || !srv.ToolPolicy("mitre_lookup").RequiresApproval {
		t.Fatal("replacement inherited privileged policy")
	}
}
