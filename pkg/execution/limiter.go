// Package execution bounds in-flight tool work and enforces server-side policy.
package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

type Limiter struct {
	active   chan struct{}
	admitted chan struct{}
	timeout  time.Duration
}

func NewLimiter(maxConcurrent, maxQueued int, timeout time.Duration) (*Limiter, error) {
	if maxConcurrent < 1 || maxConcurrent > 256 || maxQueued < 0 || maxQueued > 4096 || timeout <= 0 {
		return nil, fmt.Errorf("invalid execution concurrency, queue or timeout limits")
	}
	return &Limiter{active: make(chan struct{}, maxConcurrent), admitted: make(chan struct{}, maxConcurrent+maxQueued), timeout: timeout}, nil
}

func failure(text string) *mcp.ToolResult {
	return &mcp.ToolResult{IsError: true, Content: []mcp.ContentBlock{{Type: "text", Text: text}}}
}

func (l *Limiter) Middleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, name string, args json.RawMessage) (*mcp.ToolResult, error) {
		select {
		case l.admitted <- struct{}{}:
			defer func() { <-l.admitted }()
		default:
			return failure("execution queue full; request was not executed"), nil
		}
		ctx, cancel := context.WithTimeout(ctx, l.timeout)
		defer cancel()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case l.active <- struct{}{}:
			defer func() { <-l.active }()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := next(ctx, name, args)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return result, err
	}
}

// Approval uses operator-owned startup configuration, never a model-supplied
// "approved" parameter. Tools are approved individually; no wildcard is accepted.
func Approval(approved []string) mcp.Middleware {
	allowed := make(map[string]bool, len(approved))
	for _, name := range approved {
		allowed[name] = true
	}
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, name string, args json.RawMessage) (*mcp.ToolResult, error) {
			if mcp.PolicyFromContext(ctx).RequiresApproval && !allowed[name] {
				return failure(fmt.Sprintf("tool %q requires operator approval; add its exact name to REDHANDS_APPROVED_TOOLS after reviewing its full capabilities", name)), nil
			}
			return next(ctx, name, args)
		}
	}
}
