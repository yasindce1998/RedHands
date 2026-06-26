package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type GitOpsPoisonInput struct {
	Action     string `json:"action"`
	Controller string `json:"controller,omitempty"`
	Repo       string `json:"repo,omitempty"`
	Path       string `json:"path,omitempty"`
	Payload    string `json:"payload,omitempty"`
}

type GitOpsPoisonTool struct {
	exec executor.Executor
}

func NewGitOpsPoison(exec executor.Executor) *GitOpsPoisonTool {
	return &GitOpsPoisonTool{exec: exec}
}

func (t *GitOpsPoisonTool) Name() string { return "kubedagger_gitops_poison" }

func (t *GitOpsPoisonTool) Description() string {
	return "Poison GitOps controllers (ArgoCD, Flux) by intercepting git-sync operations or manipulating the reconciliation loop. Can inject manifests during sync, modify resources post-apply, or backdoor the controller's git credentials."
}

func (t *GitOpsPoisonTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["intercept-sync", "inject-manifest", "steal-creds", "modify-reconcile", "status"],
				"description": "GitOps poisoning action"
			},
			"controller": {
				"type": "string",
				"enum": ["argocd", "flux", "auto"],
				"description": "Target GitOps controller"
			},
			"repo": {
				"type": "string",
				"description": "Target git repository"
			},
			"path": {
				"type": "string",
				"description": "Manifest path to inject into"
			},
			"payload": {
				"type": "string",
				"description": "Manifest content to inject"
			}
		},
		"required": ["action"]
	}`)
}

func (t *GitOpsPoisonTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input GitOpsPoisonInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Repo, "repo"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Path, "path"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Payload, "payload"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"gitops-poison", "--action", input.Action}
	if input.Controller != "" {
		args = append(args, "--controller", input.Controller)
	}
	if input.Repo != "" {
		args = append(args, "--repo", input.Repo)
	}
	if input.Path != "" {
		args = append(args, "--path", input.Path)
	}
	if input.Payload != "" {
		args = append(args, "--payload", input.Payload)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger gitops-poison failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger GitOps Poison: %s\n\n", input.Action)
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
