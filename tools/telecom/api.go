package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// defaultDefenseBaseURL matches the staticzero-defense HTTP server default
// listen address (config.server.listen_addr in defense/src/config.rs).
const defaultDefenseBaseURL = "http://127.0.0.1:9100"

const maxDefenseResponseBytes = 1 << 20

var defenseHTTPClient = &http.Client{Timeout: 15 * time.Second}

// defenseAPITool issues a read-only GET against a RUNNING staticzero-defense
// engine's HTTP API (defense/src/server.rs routes). It never starts, stops,
// or reconfigures the engine.
type defenseAPITool struct {
	name        string
	title       string
	description string
	apiPath     string
}

func (t *defenseAPITool) Name() string        { return t.name }
func (t *defenseAPITool) Description() string { return t.description }

func (t *defenseAPITool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"base_url": {
				"type": "string",
				"description": "Base URL of the running staticzero-defense HTTP API (default ` + defaultDefenseBaseURL + `)"
			},
			"allow_remote": {
				"type": "boolean",
				"description": "Permit a non-loopback base_url host (default false; loopback only)"
			}
		}
	}`)
}

type apiInput struct {
	BaseURL     string `json:"base_url,omitempty"`
	AllowRemote bool   `json:"allow_remote,omitempty"`
}

func (t *defenseAPITool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input apiInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.BaseURL, "base_url"); err != nil {
		return errorResult(err.Error()), nil
	}
	u, err := validateBaseURL(input.BaseURL, input.AllowRemote)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// Only scheme + host from the user-supplied URL are used; the API path is
	// fixed per tool, so the base_url cannot redirect the request elsewhere.
	endpoint := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, t.apiPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errorResult("create request failed: " + err.Error()), nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := defenseHTTPClient.Do(req)
	if err != nil {
		return errorResult(fmt.Sprintf("defense engine request failed (is staticzero-defense running at %s://%s?): %v", u.Scheme, u.Host, err)), nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDefenseResponseBytes))
	if err != nil {
		return errorResult("read response failed: " + err.Error()), nil
	}
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		bodyText = "(empty response body)"
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errorResult(fmt.Sprintf("defense engine returned HTTP %d for %s: %s", resp.StatusCode, t.apiPath, bodyText)), nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## StaticZero Defense Engine — %s\n\n", t.title)
	fmt.Fprintf(&sb, "- **Endpoint:** GET %s\n\n", endpoint)
	sb.WriteString("```json\n")
	sb.WriteString(bodyText)
	sb.WriteString("\n```\n")

	return textResult(sb.String()), nil
}

// NewThreats returns a tool that fetches recently correlated telecom threats.
func NewThreats() *defenseAPITool {
	return &defenseAPITool{
		name:        "telecom_threats",
		title:       "Recent Threats",
		description: "Fetch the most recently correlated telecom threats (up to 50) from a running StaticZero defense engine via GET /api/v1/threats. Read-only query of engine state; requires the engine to already be running." + authorizedUseNotice,
		apiPath:     "/api/v1/threats",
	}
}

// NewAlerts returns a tool that fetches recent raw defense alerts.
func NewAlerts() *defenseAPITool {
	return &defenseAPITool{
		name:        "telecom_alerts",
		title:       "Recent Alerts",
		description: "Fetch the most recent raw defense alerts (up to 100) from a running StaticZero defense engine via GET /api/v1/alerts. Read-only query of engine state; requires the engine to already be running." + authorizedUseNotice,
		apiPath:     "/api/v1/alerts",
	}
}

// NewStats returns a tool that fetches defense engine statistics.
func NewStats() *defenseAPITool {
	return &defenseAPITool{
		name:        "telecom_stats",
		title:       "Engine Statistics",
		description: "Fetch runtime statistics (uptime, events processed, threats detected, correlation and false-positive counters) from a running StaticZero defense engine via GET /api/v1/stats. Read-only query of engine state; requires the engine to already be running." + authorizedUseNotice,
		apiPath:     "/api/v1/stats",
	}
}
