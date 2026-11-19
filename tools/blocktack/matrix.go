package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// MatrixTool runs `blocktack matrix --json`: the full weakness taxonomy
// (53 weakness classes across six layers L0-L5, each with remediation
// guidance). Pure local read; the reference vocabulary for grounding
// findings, playbooks, and report reasoning.
type MatrixTool struct {
	exec executor.Executor
}

// NewMatrix constructs the blocktack_matrix tool.
func NewMatrix(exec executor.Executor) *MatrixTool {
	return &MatrixTool{exec: exec}
}

func (t *MatrixTool) Name() string { return "blocktack_matrix" }

func (t *MatrixTool) Description() string {
	return "Print the BlockTack weakness taxonomy (blocktack matrix --json): machine-readable weakness classes across six layers — L0 infrastructure, L1 node & consensus, L2 contracts & programs, L3 cross-chain, L4 off-chain, L5 economic & governance — each with remediation guidance. Pure local lookup; use it to ground weakness IDs (BTV-L<layer>-<n>) that findings, playbooks, and reports reference. Optional weakness (exact ID) or layer (e.g. L2) filters narrow the output." + authorizedUseNotice
}

func (t *MatrixTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"weakness": {
				"type": "string",
				"description": "Exact weakness ID filter (e.g. BTV-L2-003); returns that single entry"
			},
			"layer": {
				"type": "string",
				"description": "Layer ID filter (e.g. L2); returns only that layer's weaknesses"
			}
		}
	}`)
}

func (t *MatrixTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Weakness string `json:"weakness"`
		Layer    string `json:"layer"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateSafeString(input.Weakness, "weakness"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Layer, "layer"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Weakness != "" && input.Layer != "" {
		return errorResult("weakness and layer filters are mutually exclusive"), nil
	}

	result, err := runCLI(ctx, t.exec, "matrix", "--json")
	if err != nil {
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		return failureResult("blocktack matrix", result, err), nil
	}
	if result == nil || len(result.Stdout) == 0 {
		return errorResult("blocktack matrix produced no output"), nil
	}

	filtered, summary, err := filterTaxonomy(result.Stdout, input.Weakness, input.Layer)
	if err != nil {
		return errorResult("blocktack matrix output could not be parsed: " + err.Error()), nil
	}
	return jsonResult("## BlockTack Weakness Taxonomy", summary, filtered), nil
}

// filterTaxonomy applies the optional weakness/layer filters to a taxonomy
// JSON document and returns the (possibly filtered) document plus a
// human-readable summary.
func filterTaxonomy(payload []byte, weakness, layer string) (json.RawMessage, string, error) {
	var tax struct {
		Version int `json:"version"`
		Layers  []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Weaknesses  []struct {
				ID          string   `json:"id"`
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Remediation string   `json:"remediation"`
				Tags        []string `json:"tags"`
			} `json:"weaknesses"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(payload, &tax); err != nil {
		return nil, "", err
	}

	total := 0
	for _, l := range tax.Layers {
		total += len(l.Weaknesses)
	}
	summary := fmt.Sprintf("- **Taxonomy version:** %d\n- **Layers:** %d\n- **Weaknesses:** %d", tax.Version, len(tax.Layers), total)

	if weakness == "" && layer == "" {
		return json.RawMessage(strings.TrimSpace(string(payload))), summary, nil
	}

	out := map[string]any{"version": tax.Version, "layers": []any{}}
	matched := 0
	layers := []any{}
	for _, l := range tax.Layers {
		if layer != "" && l.ID != layer {
			continue
		}
		keep := []any{}
		for _, w := range l.Weaknesses {
			if weakness != "" && w.ID != weakness {
				continue
			}
			matched++
			keep = append(keep, w)
		}
		if len(keep) == 0 && weakness != "" {
			continue
		}
		layers = append(layers, map[string]any{
			"id": l.ID, "name": l.Name, "description": l.Description, "weaknesses": keep,
		})
	}
	out["layers"] = layers
	if matched == 0 {
		return nil, "", fmt.Errorf("no taxonomy entry matches weakness=%q layer=%q", weakness, layer)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return json.RawMessage(data), fmt.Sprintf("- **Filtered:** %d matching weaknesses", matched), nil
}
