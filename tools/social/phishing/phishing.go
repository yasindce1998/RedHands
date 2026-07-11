package phishing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Client manages HTTP communication with the GoPhish API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient creates a new GoPhish API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{baseURL: baseURL, apiKey: apiKey, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	url := strings.TrimRight(c.baseURL, "/") + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// ---------- CampaignCreateTool ----------

type CampaignCreateTool struct {
	client *Client
}

func NewCampaignCreate(client *Client) *CampaignCreateTool {
	return &CampaignCreateTool{client: client}
}

type campaignCreateInput struct {
	Name          string `json:"name"`
	TemplateID    int    `json:"template_id"`
	LandingPageID int    `json:"landing_page_id"`
	GroupIDs      []int  `json:"group_ids"`
	SMTPID        int    `json:"smtp_id"`
	URL           string `json:"url,omitempty"`
}

func (t *CampaignCreateTool) Name() string { return "phishing_campaign_create" }

func (t *CampaignCreateTool) Description() string {
	return "Create a new phishing campaign in GoPhish. Requires a template, landing page, target group(s), and SMTP sending profile."
}

func (t *CampaignCreateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {
				"type": "string",
				"description": "Name of the phishing campaign"
			},
			"template_id": {
				"type": "integer",
				"description": "ID of the email template to use"
			},
			"landing_page_id": {
				"type": "integer",
				"description": "ID of the landing page to use"
			},
			"group_ids": {
				"type": "array",
				"items": {"type": "integer"},
				"description": "IDs of the target groups"
			},
			"smtp_id": {
				"type": "integer",
				"description": "ID of the SMTP sending profile"
			},
			"url": {
				"type": "string",
				"description": "URL to use in the phishing email (optional)"
			}
		},
		"required": ["name", "template_id", "landing_page_id", "group_ids", "smtp_id"]
	}`)
}

func (t *CampaignCreateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input campaignCreateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Name); err != nil {
		return errorResult("name: " + err.Error()), nil
	}
	if input.TemplateID <= 0 {
		return errorResult("template_id is required and must be positive"), nil
	}
	if input.LandingPageID <= 0 {
		return errorResult("landing_page_id is required and must be positive"), nil
	}
	if len(input.GroupIDs) == 0 {
		return errorResult("group_ids is required and must not be empty"), nil
	}
	if input.SMTPID <= 0 {
		return errorResult("smtp_id is required and must be positive"), nil
	}

	payload := map[string]any{
		"name": input.Name,
		"template": map[string]any{
			"id": input.TemplateID,
		},
		"page": map[string]any{
			"id": input.LandingPageID,
		},
		"smtp": map[string]any{
			"id": input.SMTPID,
		},
		"groups": func() []map[string]any {
			groups := make([]map[string]any, len(input.GroupIDs))
			for i, id := range input.GroupIDs {
				groups[i] = map[string]any{"id": id}
			}
			return groups
		}(),
	}
	if input.URL != "" {
		payload["url"] = input.URL
	}

	respBody, err := t.client.do(ctx, http.MethodPost, "/api/campaigns/", payload)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return textResult(string(respBody)), nil
}

// ---------- CampaignStatusTool ----------

type CampaignStatusTool struct {
	client *Client
}

func NewCampaignStatus(client *Client) *CampaignStatusTool {
	return &CampaignStatusTool{client: client}
}

type campaignStatusInput struct {
	CampaignID int `json:"campaign_id"`
}

func (t *CampaignStatusTool) Name() string { return "phishing_campaign_status" }

func (t *CampaignStatusTool) Description() string {
	return "Get the current status and results of a phishing campaign from GoPhish."
}

func (t *CampaignStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"campaign_id": {
				"type": "integer",
				"description": "ID of the campaign to query"
			}
		},
		"required": ["campaign_id"]
	}`)
}

func (t *CampaignStatusTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input campaignStatusInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.CampaignID <= 0 {
		return errorResult("campaign_id is required and must be positive"), nil
	}

	path := fmt.Sprintf("/api/campaigns/%d", input.CampaignID)
	respBody, err := t.client.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return textResult(string(respBody)), nil
}

// ---------- TemplateTool ----------

type TemplateTool struct {
	client *Client
}

func NewTemplateCreate(client *Client) *TemplateTool {
	return &TemplateTool{client: client}
}

type templateCreateInput struct {
	Name        string   `json:"name"`
	Subject     string   `json:"subject"`
	HTML        string   `json:"html,omitempty"`
	Text        string   `json:"text,omitempty"`
	Attachments []string `json:"attachments,omitempty"`
}

func (t *TemplateTool) Name() string { return "phishing_template_create" }

func (t *TemplateTool) Description() string {
	return "Create a new email template in GoPhish for use in phishing campaigns."
}

func (t *TemplateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {
				"type": "string",
				"description": "Name of the email template"
			},
			"subject": {
				"type": "string",
				"description": "Email subject line"
			},
			"html": {
				"type": "string",
				"description": "HTML body of the email"
			},
			"text": {
				"type": "string",
				"description": "Plain text body of the email"
			},
			"attachments": {
				"type": "array",
				"items": {"type": "string"},
				"description": "List of attachment file paths"
			}
		},
		"required": ["name", "subject"]
	}`)
}

func (t *TemplateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input templateCreateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Name); err != nil {
		return errorResult("name: " + err.Error()), nil
	}
	if err := validateInput(input.Subject); err != nil {
		return errorResult("subject: " + err.Error()), nil
	}

	payload := map[string]any{
		"name":    input.Name,
		"subject": input.Subject,
	}
	if input.HTML != "" {
		payload["html"] = input.HTML
	}
	if input.Text != "" {
		payload["text"] = input.Text
	}
	if len(input.Attachments) > 0 {
		attachments := make([]map[string]any, len(input.Attachments))
		for i, a := range input.Attachments {
			attachments[i] = map[string]any{"name": a}
		}
		payload["attachments"] = attachments
	}

	respBody, err := t.client.do(ctx, http.MethodPost, "/api/templates/", payload)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return textResult(string(respBody)), nil
}

// ---------- LandingPageTool ----------

type LandingPageTool struct {
	client *Client
}

func NewLandingPageCreate(client *Client) *LandingPageTool {
	return &LandingPageTool{client: client}
}

type landingPageCreateInput struct {
	Name               string `json:"name"`
	HTML               string `json:"html"`
	CaptureCredentials bool   `json:"capture_credentials,omitempty"`
	CapturePasswords   bool   `json:"capture_passwords,omitempty"`
	RedirectURL        string `json:"redirect_url,omitempty"`
}

func (t *LandingPageTool) Name() string { return "phishing_landing_create" }

func (t *LandingPageTool) Description() string {
	return "Create a new landing page in GoPhish for credential harvesting or redirection."
}

func (t *LandingPageTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {
				"type": "string",
				"description": "Name of the landing page"
			},
			"html": {
				"type": "string",
				"description": "HTML content of the landing page"
			},
			"capture_credentials": {
				"type": "boolean",
				"description": "Whether to capture submitted credentials (default: false)"
			},
			"capture_passwords": {
				"type": "boolean",
				"description": "Whether to capture passwords in addition to usernames (default: false)"
			},
			"redirect_url": {
				"type": "string",
				"description": "URL to redirect victims to after form submission"
			}
		},
		"required": ["name", "html"]
	}`)
}

func (t *LandingPageTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input landingPageCreateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Name); err != nil {
		return errorResult("name: " + err.Error()), nil
	}
	if input.HTML == "" {
		return errorResult("html is required"), nil
	}

	payload := map[string]any{
		"name":               input.Name,
		"html":               input.HTML,
		"capture_credentials": input.CaptureCredentials,
		"capture_passwords":   input.CapturePasswords,
	}
	if input.RedirectURL != "" {
		payload["redirect_url"] = input.RedirectURL
	}

	respBody, err := t.client.do(ctx, http.MethodPost, "/api/pages/", payload)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return textResult(string(respBody)), nil
}

// ---------- GroupsTool ----------

type GroupsTool struct {
	client *Client
}

func NewGroupsCreate(client *Client) *GroupsTool {
	return &GroupsTool{client: client}
}

type target struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Position  string `json:"position,omitempty"`
}

type groupsCreateInput struct {
	Name    string   `json:"name"`
	Targets []target `json:"targets"`
}

func (t *GroupsTool) Name() string { return "phishing_groups_create" }

func (t *GroupsTool) Description() string {
	return "Create a target group in GoPhish containing email addresses and metadata for phishing campaigns."
}

func (t *GroupsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {
				"type": "string",
				"description": "Name of the target group"
			},
			"targets": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"email": {
							"type": "string",
							"description": "Target email address"
						},
						"first_name": {
							"type": "string",
							"description": "Target first name"
						},
						"last_name": {
							"type": "string",
							"description": "Target last name"
						},
						"position": {
							"type": "string",
							"description": "Target job position/title"
						}
					},
					"required": ["email"]
				},
				"description": "List of targets for the group"
			}
		},
		"required": ["name", "targets"]
	}`)
}

func (t *GroupsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input groupsCreateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Name); err != nil {
		return errorResult("name: " + err.Error()), nil
	}
	if len(input.Targets) == 0 {
		return errorResult("targets is required and must not be empty"), nil
	}

	for i, tgt := range input.Targets {
		if tgt.Email == "" {
			return errorResult(fmt.Sprintf("target[%d]: email is required", i)), nil
		}
	}

	payload := map[string]any{
		"name":    input.Name,
		"targets": input.Targets,
	}

	respBody, err := t.client.do(ctx, http.MethodPost, "/api/groups/", payload)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return textResult(string(respBody)), nil
}
