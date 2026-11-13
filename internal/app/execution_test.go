package app

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type restrictedTestTool struct{ calls *int }

func (t restrictedTestTool) Name() string        { return "restricted_test" }
func (t restrictedTestTool) Description() string { return "test policy" }
func (t restrictedTestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}
func (t restrictedTestTool) Execute(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
	(*t.calls)++
	return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "executed"}}}, nil
}

func TestWorkflowAndDirectCallsShareApproval(t *testing.T) {
	for _, mode := range []string{"blocked", "approved", "dry-run"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Load()
			cfg.DryRun = mode == "dry-run"
			if mode == "approved" {
				cfg.ApprovedTools = []string{"restricted_test"}
			}
			logger, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = logger.Close() })
			srv := mcp.NewServer("test", "1")
			SetupMiddleware(srv, &cfg, logger, auth.Config{Mode: "none"}, nil)
			calls := 0
			_ = srv.RegisterTool(restrictedTestTool{calls: &calls})
			SetupWorkflow(srv)
			direct, err := srv.ExecuteTool(context.Background(), "restricted_test", json.RawMessage(`{"approved":true}`))
			if err != nil {
				t.Fatal(err)
			}
			response := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"restricted_test","params":{"approved":true}}]}}`))
			switch mode {
			case "approved":
				if calls != 2 || direct.IsError {
					t.Fatalf("approved tool blocked: %s", response)
				}
			case "blocked":
				if calls != 0 || !direct.IsError || !bytes.Contains(response, []byte("operator approval")) {
					t.Fatalf("approval bypassed: %s", response)
				}
			case "dry-run":
				if calls != 0 || direct.IsError || !bytes.Contains(response, []byte("DRY-RUN")) {
					t.Fatalf("dry-run executed: %s", response)
				}
			}
		})
	}
}
