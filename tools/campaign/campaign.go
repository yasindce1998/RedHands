// Package campaign exposes the RedHands multi-step campaign engine as
// standard MCP tools. Campaigns were previously reachable only through the
// custom campaign/* JSON-RPC methods; these thin wrappers delegate to the
// exact same engine handlers (workflow.EnhancedEngine's *FromJSON methods)
// so MCP clients that only discover tools see them.
package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Engine is the subset of workflow.EnhancedEngine that the campaign tools
// delegate to. It mirrors the campaign/* JSON-RPC handler signatures one to
// one; *workflow.EnhancedEngine satisfies it. It is defined locally so the
// tools do not depend on the protocol layer's types.
type Engine interface {
	RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
	StatusFromJSON(params json.RawMessage) (json.RawMessage, error)
	ListFromJSON(params json.RawMessage) (json.RawMessage, error)
	ResumeFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
	CancelFromJSON(params json.RawMessage) (json.RawMessage, error)
	TemplatesFromJSON(params json.RawMessage) (json.RawMessage, error)
	GetTemplateFromJSON(params json.RawMessage) (json.RawMessage, error)
	SaveTemplateFromJSON(params json.RawMessage) (json.RawMessage, error)
}

// idPattern mirrors workflow.ValidWorkflowID and the template manager's
// name rule (letters, digits, underscore, dash; 1-64 chars). Validated
// locally instead of importing the engine's unexported helpers.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// validID reports whether s is a safe workflow or template identifier.
func validID(s string) bool { return idPattern.MatchString(s) }

const idRule = "must be 1-64 characters of letters, digits, underscore, or dash"

func errorResult(msg string) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}, nil
}

// requireObject rejects params that are not a single JSON object, so the
// engine handlers never see arrays or scalars where they expect an object.
func requireObject(params json.RawMessage) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(params, &probe); err != nil {
		return fmt.Errorf("params must be a JSON object: %v", err)
	}
	return nil
}

// normalizeObject returns params as a JSON object, defaulting empty or nil
// input to {}. Use for tools that take no parameters.
func normalizeObject(params json.RawMessage) (json.RawMessage, error) {
	if len(params) == 0 || string(params) == "null" {
		return json.RawMessage(`{}`), nil
	}
	if err := requireObject(params); err != nil {
		return nil, err
	}
	return params, nil
}

// resultField extracts a top-level string field from an engine JSON result.
func resultField(data json.RawMessage, field string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return ""
	}
	raw, ok := obj[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// renderResult wraps an engine JSON result as markdown: a plain-language
// summary line first, the raw JSON in a fenced block, then guidance.
func renderResult(summary, guidance string, data json.RawMessage) (*mcp.ToolResult, error) {
	var sb strings.Builder
	sb.WriteString(summary)
	sb.WriteString("\n\n```json\n")
	sb.Write(data)
	sb.WriteString("\n```\n\n")
	sb.WriteString(guidance)
	sb.WriteString("\n")
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
