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
	Repo        string `json:"repo,omitempty"`
	TargetPath  string `json:"target_path,omitempty"`
	InjectImage string `json:"inject_image,omitempty"`
}

type GitOpsPoisonTool struct {
	exec executor.Executor
}

func NewGitOpsPoison(exec executor.Executor) *GitOpsPoisonTool {
	return &GitOpsPoisonTool{exec: exec}
}

func (t *GitOpsPoisonTool) Name() string { return "kubedagger_gitops_poison" }

func (t *GitOpsPoisonTool) Description() string {
	return "Poison GitOps pipelines (ArgoCD, Flux) by tampering with the source repository. Clones the repo, replaces the image reference at the target manifest path with an attacker-controlled image, and pushes the change so the controller rolls it out."
}

func (t *GitOpsPoisonTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"repo": {
				"type": "string",
				"description": "Target git repository URL"
			},
			"target_path": {
				"type": "string",
				"description": "Path within the repo of the manifest to poison"
			},
			"inject_image": {
				"type": "string",
				"description": "Attacker-controlled image reference to inject"
			}
		}
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
	if err := validateSafeString(input.TargetPath, "target_path"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.InjectImage, "inject_image"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"gitops-poison"}
	if input.Repo != "" {
		args = append(args, "--repo", input.Repo)
	}
	if input.TargetPath != "" {
		args = append(args, "--target-path", input.TargetPath)
	}
	if input.InjectImage != "" {
		args = append(args, "--inject-image", input.InjectImage)
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
	sb.WriteString("## KubeDagger GitOps Poison\n\n")
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
