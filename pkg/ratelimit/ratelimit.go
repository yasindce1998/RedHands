package ratelimit

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

type Limiter struct {
	rate    int
	burst   int
	tokens  int
	mu      sync.Mutex
	lastAdd time.Time
}

func New(rate, burst int) *Limiter {
	return &Limiter{
		rate:    rate,
		burst:   burst,
		tokens:  burst,
		lastAdd: time.Now(),
	}
}

func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastAdd)
	add := int(elapsed.Seconds() * float64(l.rate))
	if add > 0 {
		l.tokens += add
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastAdd = now
	}

	if l.tokens <= 0 {
		return false
	}
	l.tokens--
	return true
}

func Middleware(limiter *Limiter) mcp.Middleware {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
			if !limiter.Allow() {
				return &mcp.ToolResult{
					Content: []mcp.ContentBlock{{Type: "text", Text: "rate limit exceeded, please try again later"}},
					IsError: true,
				}, nil
			}
			return next(ctx, toolName, params)
		}
	}
}
