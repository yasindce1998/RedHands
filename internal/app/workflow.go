package app

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/config"
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
func SetupCampaign(srv *mcp.Server, cfg *config.Config, targetDB *targetdb.Store) *workflow.EnhancedEngine {
	engine := workflow.NewEnhancedEngine(
		toolExecutor(srv),
		cfg.WorkflowStateDir,
		cfg.WorkflowTemplateDir,
		cfg.WorkflowMaxParallel,
	)
	if targetDB != nil {
		engine.SetRecorder(NewCampaignRecorder(targetDB))
	}
	srv.SetCampaignEngine(engine)
	return engine
}
