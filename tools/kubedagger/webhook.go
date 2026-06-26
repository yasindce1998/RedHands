package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type WebhookInput struct {
	Action    string `json:"action"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port,omitempty"`
	Intercept string `json:"intercept,omitempty"`
}

type WebhookTool struct {
	exec executor.Executor
}

func NewWebhook(exec executor.Executor) *WebhookTool {
	return &WebhookTool{exec: exec}
}

func (t *WebhookTool) Name() string { return "kubedagger_webhook" }

func (t *WebhookTool) Description() string {
	return "Deploy or remove a malicious mutating admission webhook that intercepts pod creation requests. Can inject sidecar containers, modify security contexts, or steal secrets from pod specifications."
}

func (t *WebhookTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "remove", "status"],
				"description": "Webhook action: deploy, remove, or check status"
			},
			"name": {
				"type": "string",
				"description": "Webhook name"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace to target with the webhook"
			},
			"target": {
				"type": "string",
				"description": "Webhook callback target URL or service"
			},
			"port": {
				"type": "integer",
				"description": "Webhook service port"
			},
			"intercept": {
				"type": "string",
				"enum": ["pods", "deployments", "secrets", "all"],
				"description": "Resource types to intercept"
			}
		},
		"required": ["action"]
	}`)
}

func (t *WebhookTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input WebhookInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"webhook", input.Action}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Intercept != "" {
		args = append(args, "--intercept", input.Intercept)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger webhook failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Webhook: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation complete.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
