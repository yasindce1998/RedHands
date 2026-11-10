package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func Middleware(logger Logger) mcp.Middleware {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, toolName string, params json.RawMessage) (*mcp.ToolResult, error) {
			start := time.Now()

			result, err := next(ctx, toolName, params)

			event := AuditEvent{
				ID:        generateID(),
				Timestamp: start,
				Actor:     "mcp-client",
				Action:    "tools/call",
				Tool:      toolName,
				Params:    params,
				Duration:  time.Since(start).Milliseconds(),
			}
			if identity, _ := ctx.Value(auth.ContextKeyIdentity).(string); identity != "" {
				event.Actor = identity
			}

			if err != nil {
				event.Result = "error"
				event.Error = err.Error()
			} else if result != nil && result.IsError {
				event.Result = "error"
				if len(result.Content) > 0 {
					event.Error = result.Content[0].Text
				}
			} else {
				event.Result = "success"
			}

			if err := logger.Log(ctx, event); err != nil {
				log.Printf("audit: log event failed: %v", err)
			}

			return result, err
		}
	}
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
