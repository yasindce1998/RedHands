package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// tasksExtensionKey marks a request context whose request declared the
// io.modelcontextprotocol/tasks client capability extension in
// params._meta.clientCapabilities.extensions. It is set once per request by
// handleRequest and read by engine-side handlers and the approval
// middleware, so every request is negotiated independently (correct on
// stdio, TCP, and HTTP, where each request carries its own _meta).
type tasksExtensionKey struct{}

// WithTasksExtension marks ctx as carrying the tasks extension capability.
func WithTasksExtension(ctx context.Context) context.Context {
	return context.WithValue(ctx, tasksExtensionKey{}, true)
}

// TasksExtensionEnabled reports whether the request that produced ctx
// declared the io.modelcontextprotocol/tasks extension.
func TasksExtensionEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(tasksExtensionKey{}).(bool)
	return enabled
}

// inputResponsesKey carries the per-call inputResponses map (tasks
// extension / MRTR approval round-trip) from JSON-RPC params into the tool
// execution context. Only the approval middleware consumes it, and only
// when the same request also declared the tasks extension; storing it for
// capability-less requests is therefore harmless but never honored.
type inputResponsesKey struct{}

// ApprovalInputKey is the inputRequests/inputResponses key under which
// operator approval is requested and answered.
const ApprovalInputKey = "approval"

// WithInputResponses attaches inputResponses to ctx. Values are read-only
// from this point on.
func WithInputResponses(ctx context.Context, responses map[string]json.RawMessage) context.Context {
	return context.WithValue(ctx, inputResponsesKey{}, responses)
}

// InputResponsesFromContext returns the inputResponses map the current
// call carried, or nil when the request had none.
func InputResponsesFromContext(ctx context.Context) map[string]json.RawMessage {
	responses, _ := ctx.Value(inputResponsesKey{}).(map[string]json.RawMessage)
	return responses
}

// IsAffirmativeApproval reports whether an inputResponses["approval"]
// payload grants approval. The concrete contract (documented where the
// spec is ambiguous): the payload must be a JSON object whose "approved"
// field is the literal boolean true. Anything else — a non-object, a
// missing field, false, or a non-boolean — is a denial. A stateless server
// cannot cryptographically bind the response to the elicitation it issued,
// so the trust boundary is the per-request tasks-extension capability
// declaration, which is exactly how MCP elicitation works: the client is
// trusted to have obtained operator consent.
func IsAffirmativeApproval(resp json.RawMessage) bool {
	if len(resp) == 0 {
		return false
	}
	var decision struct {
		Approved *bool `json:"approved"`
	}
	if err := json.Unmarshal(resp, &decision); err != nil || decision.Approved == nil {
		return false
	}
	return *decision.Approved
}

// NewRequestID mints a unique identifier for an elicitation inputRequest.
func NewRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on the supported platforms; fall back to
		// a time-based id rather than panicking mid-request.
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return "req_" + hex.EncodeToString(b)
}
