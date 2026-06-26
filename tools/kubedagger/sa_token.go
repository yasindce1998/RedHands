package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SATokenInput struct {
	Action    string `json:"action"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Account   string `json:"account,omitempty"`
}

type SATokenTool struct {
	exec executor.Executor
}

func NewSAToken(exec executor.Executor) *SATokenTool {
	return &SATokenTool{exec: exec}
}

func (t *SATokenTool) Name() string { return "kubedagger_sa_token" }

func (t *SATokenTool) Description() string {
	return "Harvest Kubernetes service account tokens from pods by reading projected volumes or intercepting TokenRequest API calls via eBPF. Extracted tokens can be used for lateral movement through the cluster API."
}

func (t *SATokenTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["harvest", "intercept", "enumerate", "use"],
				"description": "Token operation"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			},
			"pod": {
				"type": "string",
				"description": "Target pod name"
			},
			"account": {
				"type": "string",
				"description": "Service account name to target"
			}
		},
		"required": ["action"]
	}`)
}

func (t *SATokenTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SATokenInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Account, "account"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"sa-token", "--action", input.Action}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Account != "" {
		args = append(args, "--account", input.Account)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger sa-token failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger SA Token: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("No tokens found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
