package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func (n *Notifier) Middleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
		result, err := next(ctx, toolName, params)
		if err != nil {
			return result, err
		}

		if result != nil && !result.IsError {
			target := extractTarget(params)
			n.Notify(ctx, Event{
				Type:    "tool_execution",
				Tool:    toolName,
				Target:  target,
				Message: fmt.Sprintf("Executed %s against %s", toolName, target),
			})
		}

		return result, err
	}
}

func extractTarget(params json.RawMessage) string {
	var p struct {
		Target string `json:"target"`
		Host   string `json:"host"`
		IP     string `json:"ip"`
	}
	json.Unmarshal(params, &p)

	if p.Target != "" {
		return p.Target
	}
	if p.Host != "" {
		return p.Host
	}
	return p.IP
}
