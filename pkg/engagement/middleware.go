package engagement

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ScopeMiddleware checks explicit network targets. It is not a network sandbox:
// redirects, DNS changes, tool-internal discovery and opaque commands require
// additional network isolation and operator review.
func (m *Manager) ScopeMiddleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, name string, params json.RawMessage) (*mcp.ToolResult, error) {
		// These tools operate on local artifacts or engagement metadata, not hosts.
		localTarget := strings.HasPrefix(name, "barzakh_") || strings.HasPrefix(name, "mobile_") || strings.HasPrefix(name, "engagement_")
		if !localTarget {
			for _, target := range extractTargets(params) {
				if !m.InScope(target) {
					return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: fmt.Sprintf("target %q is out of scope for current engagement", target)}}, IsError: true}, nil
				}
			}
		}
		return next(ctx, name, params)
	}
}

func extractTargets(params json.RawMessage) []string {
	var p map[string]any
	if json.Unmarshal(params, &p) != nil {
		return nil
	}
	var targets []string
	var add func(any)
	add = func(value any) {
		switch v := value.(type) {
		case string:
			targets = append(targets, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' })...)
		case []any:
			for _, item := range v {
				add(item)
			}
		}
	}
	for _, key := range []string{"target", "targets", "host", "hosts", "ip", "ips", "url", "urls", "target_ip", "dc_ip", "endpoint", "server"} {
		add(p[key])
	}
	// A domain can be a credential realm when a target is supplied. Treat it as
	// the target only for domain-based discovery with no primary destination.
	if len(targets) == 0 {
		add(p["domain"])
		add(p["domains"])
	}
	return targets
}
