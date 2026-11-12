package msf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ModuleInfoTool shows Metasploit module documentation by driving msfconsole
// with a generated resource file (use <module>, show info, exit).
type ModuleInfoTool struct {
	exec executor.Executor
}

// NewModuleInfo creates the module documentation lookup tool.
func NewModuleInfo(exec executor.Executor) *ModuleInfoTool {
	return &ModuleInfoTool{exec: exec}
}

func (t *ModuleInfoTool) Name() string { return "msf_module_info" }

func (t *ModuleInfoTool) Description() string {
	return "Show Metasploit module documentation (description, options, authors, references, targets, actions) " +
		"by writing a small resource file (use <module>, show info, exit) into the required work_dir and running " +
		"msfconsole -q on it. Read-only module reference for any module type (exploit, auxiliary, post, payload, " +
		"encoder, nop). Note: msfconsole startup is slow (typically 10-60 seconds); execution is bounded by the " +
		"REDHANDS_TIMEOUT setting, so very slow framework loads may time out. For authorized engagements only."
}

func (t *ModuleInfoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"module": {
				"type": "string",
				"pattern": "^(exploit|auxiliary|post|payload|encoder|nop)/[a-z0-9/_.+-]+$",
				"description": "Full module reference, e.g. exploit/multi/handler, auxiliary/scanner/portscan/tcp, post/multi/manage/shell_to_meterpreter"
			},
			"work_dir": {
				"type": "string",
				"description": "Required working directory (created with 0700 if missing) where the generated resource file lands"
			}
		},
		"required": ["module", "work_dir"]
	}`)
}

type moduleInfoInput struct {
	Module  string `json:"module"`
	WorkDir string `json:"work_dir"`
}

func (t *ModuleInfoTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input moduleInfoInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	if err := validateModuleName(input.Module, "module"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateWorkDir(input.WorkDir); err != nil {
		return errorResult(err.Error()), nil
	}

	// The resource file content is assembled only from validated structured
	// parameters, so no arbitrary console commands can be injected.
	rcPath, err := writeResourceFile(input.WorkDir, "info", []string{
		"use " + input.Module,
		"show info",
	})
	if err != nil {
		return errorResult(err.Error()), nil
	}

	result, err := t.exec.Run(ctx, "msfconsole", "-q", "-r", rcPath)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("msfconsole failed: %v\n%s", err, stderr)), nil
	}

	var sb strings.Builder
	sb.WriteString("## Metasploit Module Information\n\n")
	fmt.Fprintf(&sb, "**Module**: %s\n", input.Module)
	fmt.Fprintf(&sb, "**Resource file**: %s\n\n", rcPath)
	sb.WriteString("```\n")
	if out := strings.TrimSpace(string(result.Stdout)); out != "" {
		sb.WriteString(out + "\n")
	} else {
		sb.WriteString("(no output)\n")
	}
	sb.WriteString("```\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
