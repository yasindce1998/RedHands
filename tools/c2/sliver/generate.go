package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type GenerateInput struct {
	OS       string `json:"os"`
	Arch     string `json:"arch,omitempty"`
	Format   string `json:"format,omitempty"`
	MTLS     string `json:"mtls,omitempty"`
	HTTP     string `json:"http,omitempty"`
	DNS      string `json:"dns,omitempty"`
	Name     string `json:"name,omitempty"`
	Save     string `json:"save,omitempty"`
	Debug    bool   `json:"debug,omitempty"`
	Evasion  bool   `json:"evasion,omitempty"`
}

type GenerateTool struct {
	exec executor.Executor
}

func NewGenerate(exec executor.Executor) *GenerateTool {
	return &GenerateTool{exec: exec}
}

func (t *GenerateTool) Name() string { return "sliver_generate" }

func (t *GenerateTool) Description() string {
	return "Generate a Sliver C2 implant with specified OS, architecture, C2 channels, and evasion options. Supports beacon and session modes with mTLS, HTTP/S, DNS, and WireGuard transports."
}

func (t *GenerateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"os": {
				"type": "string",
				"enum": ["windows", "linux", "darwin"],
				"description": "Target operating system"
			},
			"arch": {
				"type": "string",
				"enum": ["amd64", "arm64", "386"],
				"description": "Target architecture (default: amd64)"
			},
			"format": {
				"type": "string",
				"enum": ["exe", "shared", "service", "shellcode"],
				"description": "Output format"
			},
			"mtls": {
				"type": "string",
				"description": "mTLS C2 endpoint (host:port)"
			},
			"http": {
				"type": "string",
				"description": "HTTP(S) C2 endpoint (URL)"
			},
			"dns": {
				"type": "string",
				"description": "DNS C2 domain"
			},
			"name": {
				"type": "string",
				"description": "Implant name"
			},
			"save": {
				"type": "string",
				"description": "Save path for generated implant"
			},
			"debug": {
				"type": "boolean",
				"description": "Enable debug mode"
			},
			"evasion": {
				"type": "boolean",
				"description": "Enable evasion features"
			}
		},
		"required": ["os"]
	}`)
}

func (t *GenerateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input GenerateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateRequired(input.OS, "os"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.MTLS, "mtls"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.HTTP, "http"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.DNS, "dns"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Save, "save"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"generate", "--os", input.OS}
	if input.Arch != "" {
		args = append(args, "--arch", input.Arch)
	}
	if input.Format != "" {
		args = append(args, "--format", input.Format)
	}
	if input.MTLS != "" {
		args = append(args, "--mtls", input.MTLS)
	}
	if input.HTTP != "" {
		args = append(args, "--http", input.HTTP)
	}
	if input.DNS != "" {
		args = append(args, "--dns", input.DNS)
	}
	if input.Name != "" {
		args = append(args, "--name", input.Name)
	}
	if input.Save != "" {
		args = append(args, "--save", input.Save)
	}
	if input.Debug {
		args = append(args, "--debug")
	}
	if input.Evasion {
		args = append(args, "--evasion")
	}

	result, err := t.exec.Run(ctx, "sliver-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sliver generate failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Sliver Generate Implant\n\n")
	fmt.Fprintf(&sb, "**OS**: %s | **Arch**: %s\n\n", input.OS, input.Arch)
	if output == "" {
		sb.WriteString("Implant generated.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
