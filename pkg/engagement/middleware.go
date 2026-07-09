package engagement

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func (m *Manager) ScopeMiddleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
		target := extractTarget(params)
		if target != "" && !m.InScope(target) {
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: fmt.Sprintf("target %q is out of scope for current engagement", target)}},
				IsError: true,
			}, nil
		}
		return next(ctx, toolName, params)
	}
}

func extractTarget(params json.RawMessage) string {
	var p struct {
		Target string `json:"target"`
		Host   string `json:"host"`
		IP     string `json:"ip"`
		Domain string `json:"domain"`
	}
	json.Unmarshal(params, &p)

	if p.Target != "" {
		return p.Target
	}
	if p.Host != "" {
		return p.Host
	}
	if p.IP != "" {
		return p.IP
	}
	return p.Domain
}
