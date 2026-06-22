package mcp

import (
	"context"
	"encoding/json"
)

type Tool interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	Execute(ctx context.Context, params json.RawMessage) (*ToolResult, error)
}

type ToolHandler func(ctx context.Context, toolName string, params json.RawMessage) (*ToolResult, error)
