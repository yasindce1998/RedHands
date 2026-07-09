package dryrun

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

type LogEntry struct {
	Timestamp time.Time       `json:"timestamp"`
	Tool      string          `json:"tool"`
	Params    json.RawMessage `json:"params"`
}

type Interceptor struct {
	mu      sync.Mutex
	entries []LogEntry
}

func NewInterceptor() *Interceptor {
	return &Interceptor{}
}

func (d *Interceptor) Middleware(next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
		d.mu.Lock()
		d.entries = append(d.entries, LogEntry{
			Timestamp: time.Now(),
			Tool:      toolName,
			Params:    params,
		})
		d.mu.Unlock()

		msg := fmt.Sprintf("[DRY-RUN] Would execute tool: %s\nParams: %s", toolName, string(params))
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		}, nil
	}
}

func (d *Interceptor) Log() []LogEntry {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]LogEntry, len(d.entries))
	copy(result, d.entries)
	return result
}

func (d *Interceptor) Clear() {
	d.mu.Lock()
	d.entries = nil
	d.mu.Unlock()
}
