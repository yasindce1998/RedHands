// Package execution bounds in-flight tool work and enforces server-side policy.
package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
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
	return ApprovalWithAudit(approved, nil)
}

// ApprovalWithAudit is Approval with an audit sink for approval-bypass
// events: every call admitted through an MRTR elicitation round-trip is
// logged as Action "approval/bypass" in addition to the regular tools/call
// audit event the surrounding middleware chain already records.
func ApprovalWithAudit(approved []string, logger audit.Logger) mcp.Middleware {
	allowed := make(map[string]bool, len(approved))
	for _, name := range approved {
		allowed[name] = true
	}
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, name string, args json.RawMessage) (*mcp.ToolResult, error) {
			if mcp.PolicyFromContext(ctx).RequiresApproval && !allowed[name] {
				// MRTR (io.modelcontextprotocol/tasks): a request that
				// declared the tasks extension gets an input_required
				// result instead of a hard failure, and a re-issued call
				// carrying an affirmative inputResponses["approval"] is
				// admitted for THIS call only. The response lives in the
				// per-request context (never in the model-supplied tool
				// arguments), and it grants exactly one call: the bypass
				// does not add the tool to REDHANDS_APPROVED_TOOLS.
				if mcp.TasksExtensionEnabled(ctx) {
					if responses := mcp.InputResponsesFromContext(ctx); responses != nil {
						if response, ok := responses[mcp.ApprovalInputKey]; ok {
							if mcp.IsAffirmativeApproval(response) {
								logApprovalBypass(ctx, logger, name, response)
								return next(ctx, name, args)
							}
							// A response that is present but not
							// affirmative is an explicit denial.
							return failure(fmt.Sprintf("tool %q approval denied by operator", name)), nil
						}
					}
					return inputRequired(name), nil
				}
				// No capability declared: fail closed, exactly as before.
				return failure(fmt.Sprintf("tool %q requires operator approval; add its exact name to REDHANDS_APPROVED_TOOLS after reviewing its full capabilities", name)), nil
			}
			return next(ctx, name, args)
		}
	}
}

// inputRequired builds the MRTR result that pauses a tools/call until the
// client answers the elicitation and re-issues the same call with
// params.inputResponses. It is not an error: the call is well-formed and
// merely blocked on operator input.
func inputRequired(name string) *mcp.ToolResult {
	return &mcp.ToolResult{
		ResultType: mcp.ResultTypeInputRequired,
		Content: []mcp.ContentBlock{{
			Type: "text",
			Text: fmt.Sprintf("Tool %q requires operator approval; approve or deny via inputResponses and re-issue this call.", name),
		}},
		InputRequests: map[string]mcp.InputRequest{
			mcp.ApprovalInputKey: {
				Type:      mcp.InputRequestTypeElicitation,
				Message:   fmt.Sprintf("Tool %q requires operator approval. Review its full capabilities, then approve or deny this call.", name),
				RequestID: mcp.NewRequestID(),
			},
		},
	}
}

// logApprovalBypass records the one-call approval grant in the audit log.
func logApprovalBypass(ctx context.Context, logger audit.Logger, tool string, response json.RawMessage) {
	if logger == nil {
		return
	}
	actor := "mcp-client"
	if identity, _ := ctx.Value(auth.ContextKeyIdentity).(string); identity != "" {
		actor = identity
	}
	event := audit.AuditEvent{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    "approval/bypass",
		Tool:      tool,
		Params:    response,
		Result:    "approved via elicitation",
	}
	if err := logger.Log(ctx, event); err != nil {
		log.Printf("audit: approval-bypass log event failed: %v", err)
	}
}
