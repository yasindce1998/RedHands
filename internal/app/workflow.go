package app

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// toolExecutor adapts the server's single execution path (with its full
// middleware chain: audit, auth, rate limits, scope, dry-run, approval and
// concurrency limits) into the engine's executor signature.
func toolExecutor(srv *mcp.Server) workflow.ToolExecutor {
	return func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		result, err := srv.ExecuteTool(ctx, toolName, params)
		if err != nil {
			return "", false, err
		}
		text := ""
		for _, c := range result.Content {
			if c.Type == "text" {
				text += c.Text
			}
		}
		return text, !result.IsError, nil
	}
}

func SetupWorkflow(srv *mcp.Server) *workflow.Engine {
	wfEngine := workflow.NewEngine(toolExecutor(srv))
	srv.SetWorkflowRunner(wfEngine)
	srv.SetReportGenerator(report.NewGenerator())
	return wfEngine
}

// SetupCampaign wires the multi-stage campaign engine (campaign/run, status,
// resume, cancel, list, and playbook template methods). Every step executes
// through the server middleware chain exactly like a direct tools/call.
// When a target database is provided, record rules on steps persist
// discovered hosts, services, credentials, and findings automatically.
// When an engagement manager is provided, campaigns can bind to a named
// engagement that must be the active engagement.
func SetupCampaign(srv *mcp.Server, cfg *config.Config, targetDB *targetdb.Store, engMgr *engagement.Manager) *workflow.EnhancedEngine {
	engine := workflow.NewEnhancedEngine(
		toolExecutor(srv),
		cfg.WorkflowStateDir,
		cfg.WorkflowTemplateDir,
		cfg.WorkflowMaxParallel,
	)
	if targetDB != nil {
		engine.SetRecorder(NewCampaignRecorder(targetDB))
	}
	if engMgr != nil {
		engine.SetEngagementCheck(engagementCheck(engMgr))
	}
	srv.SetCampaignEngine(engine)
	return engine
}

// engagementCheck validates a campaign's engagement binding: the engagement
// must exist and be the active engagement, so every step's scope checks run
// against the engagement the operator intended.
func engagementCheck(mgr *engagement.Manager) func(name string) error {
	return func(name string) error {
		var found *engagement.Engagement
		for _, e := range mgr.List() {
			if e.ID == name || e.Name == name {
				found = e
				break
			}
		}
		if found == nil {
			return fmt.Errorf("engagement %q not found; create it with engagement_create", name)
		}
		active := mgr.Active()
		if active == nil || active.ID != found.ID {
			return fmt.Errorf("engagement %q is not the active engagement; switch to it with engagement_switch before running bound campaigns", name)
		}
		return nil
	}
}
