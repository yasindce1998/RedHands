package app

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

func SetupWorkflow(srv *mcp.Server) *workflow.Engine {
	wfEngine := workflow.NewEngine(func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
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
	})
	srv.SetWorkflowRunner(wfEngine)
	srv.SetReportGenerator(report.NewGenerator())
	return wfEngine
}
