package opsec

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Middleware applies OPSEC controls (delay, rate limiting, IOC tracking) to tool calls.
type Middleware struct {
	profile *Profile
	tracker *Tracker

	mu         sync.Mutex
	callCounts map[string]int // target -> calls this minute
	lastMinute time.Time
	totalCalls int
}

// NewMiddleware creates an OPSEC middleware with the given profile and IOC tracker.
func NewMiddleware(profileName string, tracker *Tracker) *Middleware {
	return &Middleware{
		profile:    GetProfile(profileName),
		tracker:    tracker,
		callCounts: make(map[string]int),
		lastMinute: time.Now(),
	}
}

// Wrap returns an MCP middleware that applies OPSEC controls.
func (m *Middleware) Wrap(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
		if m.profile.Name == "loud" {
			return next(ctx, toolName, params)
		}

		target := extractTarget(params)

		// Rate limiting
		if err := m.checkRateLimit(target); err != nil {
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Pre-execution delay with jitter
		Sleep(m.profile.MinDelay, m.profile.MaxDelay, m.profile.JitterPct, ctx.Done())

		select {
		case <-ctx.Done():
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: "cancelled by opsec delay"}},
				IsError: true,
			}, nil
		default:
		}

		// Execute
		result, err := next(ctx, toolName, params)

		// Track IOC
		if m.tracker != nil && result != nil && !result.IsError {
			m.tracker.Record(toolName, target, "tool_execution", fmt.Sprintf("%s against %s", toolName, target))
		}

		// Increment counters
		m.mu.Lock()
		m.totalCalls++
		if target != "" {
			m.callCounts[target]++
		}
		m.mu.Unlock()

		return result, err
	}
}

func (m *Middleware) checkRateLimit(target string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if now.Sub(m.lastMinute) > time.Minute {
		m.callCounts = make(map[string]int)
		m.totalCalls = 0
		m.lastMinute = now
	}

	if m.profile.MaxPerMinute > 0 && m.totalCalls >= m.profile.MaxPerMinute {
		return fmt.Errorf("opsec: rate limit exceeded (%d calls/min, profile=%s)", m.profile.MaxPerMinute, m.profile.Name)
	}

	if m.profile.MaxPerTarget > 0 && target != "" && m.callCounts[target] >= m.profile.MaxPerTarget {
		return fmt.Errorf("opsec: per-target rate limit exceeded for %s (%d calls/min, profile=%s)", target, m.profile.MaxPerTarget, m.profile.Name)
	}

	return nil
}

// extractTarget tries to pull a target/host from tool params.
func extractTarget(params json.RawMessage) string {
	var p struct {
		Target string `json:"target"`
		Host   string `json:"host"`
		IP     string `json:"ip"`
	}
	_ = json.Unmarshal(params, &p)

	if p.Target != "" {
		return p.Target
	}
	if p.Host != "" {
		return p.Host
	}
	return p.IP
}

// Profile returns the current OPSEC profile.
func (m *Middleware) CurrentProfile() *Profile {
	return m.profile
}

// SetProfile changes the active OPSEC profile.
func (m *Middleware) SetProfile(name string) {
	m.profile = GetProfile(name)
}
