package reporting

import (
	"context"
	"encoding/json"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/mitre"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type ComplianceTool struct {
	store *targetdb.Store
}

func NewComplianceTool(store *targetdb.Store) *ComplianceTool {
	return &ComplianceTool{store: store}
}

func (t *ComplianceTool) Name() string { return "report_compliance" }

func (t *ComplianceTool) Description() string {
	return "Map findings to compliance frameworks (PCI-DSS, NIST 800-53, ISO 27001)"
}

func (t *ComplianceTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"framework": {"type": "string", "description": "Filter by framework (NIST 800-53, PCI-DSS, ISO 27001)"},
			"technique_id": {"type": "string", "description": "Look up controls for a specific MITRE technique ID"}
		}
	}`)
}

func (t *ComplianceTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Framework   string `json:"framework"`
		TechniqueID string `json:"technique_id"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &input); err != nil {
			return errorResult("invalid params: " + err.Error())
		}
	}

	if input.TechniqueID != "" {
		controls := report.LookupCompliance(input.TechniqueID)
		if len(controls) == 0 {
			return textResult("No compliance mappings found for " + input.TechniqueID)
		}
		return jsonResult(controls)
	}

	if input.Framework != "" {
		controls := report.ControlsByFramework(input.Framework)
		if len(controls) == 0 {
			return textResult("No controls found for framework: " + input.Framework)
		}
		return jsonResult(controls)
	}

	findings := t.store.QueryFindings("", "", "")
	var techniqueFindings []struct {
		TechniqueID string
		Technique   string
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		for _, techID := range f.MITRE {
			if seen[techID] {
				continue
			}
			seen[techID] = true
			tech, ok := mitre.GetTechnique(techID)
			name := techID
			if ok {
				name = tech.Name
			}
			techniqueFindings = append(techniqueFindings, struct {
				TechniqueID string
				Technique   string
			}{techID, name})
		}
	}

	mappings := report.MapFindingsToCompliance(techniqueFindings)
	if len(mappings) == 0 {
		return textResult("No compliance mappings found for current findings")
	}
	return jsonResult(mappings)
}
