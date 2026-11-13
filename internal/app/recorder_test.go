package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// jsonTool is a minimal tool that returns fixed JSON output.
type jsonTool struct {
	name string
	text string
}

func (t *jsonTool) Name() string        { return t.name }
func (t *jsonTool) Description() string { return "test tool" }
func (t *jsonTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}
func (t *jsonTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: t.text}}}, nil
}

func TestCampaignRecorderMapsItemsToTargetDB(t *testing.T) {
	db := targetdb.NewStore("", false)
	recorder := NewCampaignRecorder(db)

	err := recorder.RecordStep("wf1", "scan", "test_scanner", workflow.RecordRule{
		Type: "host",
		Path: "hosts",
		Fields: map[string]string{
			"ip":       "addr",
			"hostname": "name",
			"os":       "os_guess",
		},
	}, []any{
		map[string]any{"addr": "10.0.0.1", "name": "web01", "os_guess": "Linux 5.x"},
		map[string]any{"addr": "10.0.0.2"},
	}, nil)
	if err != nil {
		t.Fatalf("record hosts: %v", err)
	}

	err = recorder.RecordStep("wf1", "svc", "test_scanner", workflow.RecordRule{
		Type: "service",
		Path: "services",
		Fields: map[string]string{
			"host": "host", "port": "port", "name": "service", "protocol": "proto",
		},
	}, []any{
		map[string]any{"host": "10.0.0.1", "port": json.Number("443"), "service": "https", "proto": "tcp"},
		map[string]any{"host": "10.0.0.1", "port": json.Number("not-a-port")}, // skipped
	}, nil)
	if err != nil {
		t.Fatalf("record services: %v", err)
	}

	err = recorder.RecordStep("wf1", "cred", "test_scanner", workflow.RecordRule{
		Type: "credential",
		Path: "creds",
		Fields: map[string]string{"username": "user", "secret": "pass", "type": "kind"},
	}, []any{
		map[string]any{"user": "admin", "pass": "hunter2", "kind": "password"},
	}, nil)
	if err != nil {
		t.Fatalf("record credentials: %v", err)
	}

	err = recorder.RecordStep("wf1", "finding", "test_scanner", workflow.RecordRule{
		Type: "finding",
		Path: "findings",
		Fields: map[string]string{
			"host": "host", "severity": "sev", "title": "title", "description": "desc",
		},
	}, []any{
		map[string]any{"host": "10.0.0.1", "sev": "critical", "title": "RCE", "desc": "Remote code execution"},
	}, []string{"T1203"})
	if err != nil {
		t.Fatalf("record findings: %v", err)
	}

	hosts := db.ListHosts()
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	// ListHosts order is map-iteration dependent; look up by IP instead.
	web, ok := db.GetHost("10.0.0.1")
	if !ok {
		t.Fatal("host 10.0.0.1 not recorded")
	}
	if web.Hostname != "web01" || web.OS != "Linux 5.x" {
		t.Errorf("host mapping wrong: %+v", web)
	}
	if _, ok := db.GetHost("10.0.0.2"); !ok {
		t.Fatal("host 10.0.0.2 not recorded")
	}
	services := db.ListServices("10.0.0.1")
	if len(services) != 1 || services[0].Port != 443 || services[0].Name != "https" {
		t.Errorf("service mapping wrong: %+v", services)
	}
	creds := db.ListCredentials()
	if len(creds) != 1 || creds[0].Username != "admin" || creds[0].Secret != "hunter2" {
		t.Errorf("credential mapping wrong: %+v", creds)
	}
	findings := db.ListFindings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" || findings[0].Tool != "test_scanner" {
		t.Errorf("finding mapping wrong: %+v", findings[0])
	}
	if len(findings[0].MITRE) != 1 || findings[0].MITRE[0] != "T1203" {
		t.Errorf("finding MITRE enrichment wrong: %v", findings[0].MITRE)
	}
}

func TestCampaignEndToEndRecordsIntoTargetDB(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	_ = srv.RegisterTool(&jsonTool{name: "fake_scan", text: "```json\n{\"hosts\":[{\"ip\":\"192.0.2.10\"},{\"ip\":\"192.0.2.11\"}]}\n```"})
	db := targetdb.NewStore("", false)
	cfg := &config.Config{WorkflowStateDir: t.TempDir(), WorkflowTemplateDir: t.TempDir(), WorkflowMaxParallel: 2}
	SetupCampaign(srv, cfg, db, nil)

	runResp := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"campaign/run","params":{"id":"e2e-record","steps":[{"id":"scan","tool":"fake_scan","mitre":["T1595.002"],"record":[{"type":"host","path":"hosts","fields":{"ip":"ip"}}]}]}}`))
	if runResp == nil || !strings.Contains(string(runResp), `"success":true`) {
		t.Fatalf("campaign run failed: %s", runResp)
	}
	if !strings.Contains(string(runResp), `"mitre_techniques":["T1595.002"]`) {
		t.Fatalf("MITRE techniques missing from result: %s", runResp)
	}
	if len(db.ListHosts()) != 2 {
		t.Fatalf("expected 2 recorded hosts, got %d", len(db.ListHosts()))
	}
	host, ok := db.GetHost("192.0.2.10")
	if !ok || host.Hostname != "" {
		t.Fatalf("recorded host wrong: %+v", host)
	}
	// Tags carry the campaign ID for traceability.
	if len(host.Tags) != 1 || host.Tags[0] != "campaign:e2e-record" {
		t.Fatalf("host campaign tag wrong: %+v", host.Tags)
	}
}
