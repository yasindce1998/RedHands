package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/mitre"
)

// MitreLookupTool looks up MITRE ATT&CK mappings for tools or techniques.
type MitreLookupTool struct{}

func NewMitreLookupTool() *MitreLookupTool {
	return &MitreLookupTool{}
}

func (t *MitreLookupTool) Name() string { return "mitre_lookup" }

func (t *MitreLookupTool) Description() string {
	return "Look up MITRE ATT&CK technique mappings for a tool name, technique ID, or tactic"
}

func (t *MitreLookupTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"tool": {"type": "string", "description": "Tool name to look up (e.g., nmap_scan, evilwinrm_shell)"},
			"technique": {"type": "string", "description": "Technique ID to look up (e.g., T1046)"},
			"tactic": {"type": "string", "description": "Tactic name to list techniques for (e.g., Lateral Movement)"}
		}
	}`)
}

func (t *MitreLookupTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Tool      string `json:"tool"`
		Technique string `json:"technique"`
		Tactic    string `json:"tactic"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &input)
	}

	if input.Tool == "" && input.Technique == "" && input.Tactic == "" {
		return errorResult("provide at least one of: tool, technique, or tactic")
	}

	var sb strings.Builder

	if input.Tool != "" {
		techniques := mitre.Lookup(input.Tool)
		if techniques == nil {
			sb.WriteString(fmt.Sprintf("No MITRE mapping found for tool: %s\n", input.Tool))
		} else {
			sb.WriteString(fmt.Sprintf("## MITRE ATT&CK Mapping: %s\n\n", input.Tool))
			for _, tech := range techniques {
				sb.WriteString(fmt.Sprintf("- **%s** - %s (Tactic: %s)\n", tech.ID, tech.Name, tech.Tactic))
			}
		}
	}

	if input.Technique != "" {
		tech, ok := mitre.GetTechnique(input.Technique)
		if !ok {
			sb.WriteString(fmt.Sprintf("Unknown technique: %s\n", input.Technique))
		} else {
			sb.WriteString(fmt.Sprintf("\n## Technique: %s\n", tech.ID))
			sb.WriteString(fmt.Sprintf("- Name: %s\n", tech.Name))
			sb.WriteString(fmt.Sprintf("- Tactic: %s\n", tech.Tactic))

			// Find which tools map to this technique
			var tools []string
			for tool, ids := range mitre.ToolMapping {
				for _, id := range ids {
					if id == input.Technique {
						tools = append(tools, tool)
						break
					}
				}
			}
			if len(tools) > 0 {
				sb.WriteString(fmt.Sprintf("- Tools: %s\n", strings.Join(tools, ", ")))
			}
		}
	}

	if input.Tactic != "" {
		techniques := mitre.TacticTechniques(input.Tactic)
		if len(techniques) == 0 {
			sb.WriteString(fmt.Sprintf("No techniques found for tactic: %s\n", input.Tactic))
		} else {
			sb.WriteString(fmt.Sprintf("\n## Tactic: %s (%d techniques)\n\n", input.Tactic, len(techniques)))
			for _, tech := range techniques {
				sb.WriteString(fmt.Sprintf("- %s: %s\n", tech.ID, tech.Name))
			}
		}
	}

	return textResult(sb.String())
}
