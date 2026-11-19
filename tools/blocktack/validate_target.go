package blocktack

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ValidateTargetTool runs `blocktack validate-target --target FILE`: a dry
// YAML parse plus guardrail verdict (authorization block presence and
// expiry, safe-mode endpoint confinement) with zero endpoint contact.
// The verdict includes the resolved endpoint list, which callers should
// feed into any downstream target-scoped calls.
type ValidateTargetTool struct {
	exec executor.Executor
}

// NewValidateTarget constructs the blocktack_validate_target tool.
func NewValidateTarget(exec executor.Executor) *ValidateTargetTool {
	return &ValidateTargetTool{exec: exec}
}

func (t *ValidateTargetTool) Name() string { return "blocktack_validate_target" }

func (t *ValidateTargetTool) Description() string {
	return "Dry-validate a BlockTack target YAML (blocktack validate-target): parses the file, checks the authorization block (declared, authorizedBy, scope, expiry) and safe-mode endpoint confinement (loopback or authorization.liveTargets), and prints a JSON verdict including the resolved endpoint list. Never contacts the endpoints. A guardrail refusal (exit 3) is reported as the verdict, not a tool failure. Call this before any target-taking BlockTack tool; treat an invalid or expired authorization as a hard stop, not a retryable error." + authorizedUseNotice
}

func (t *ValidateTargetTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the BlockTack target YAML (must carry an unexpired authorization block for anything beyond loopback endpoints)"
			}
		},
		"required": ["target"]
	}`)
}

func (t *ValidateTargetTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateInputFile(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}

	// Safe mode only: --unsafe is deliberately never passed. The refusal
	// itself is the answer, so it is rendered as a normal result.
	result, err := runCLI(ctx, t.exec, "validate-target", "--target", input.Target)
	if err != nil {
		if result != nil && len(result.Stdout) > 0 {
			// The CLI prints the full verdict JSON on stdout even when it
			// exits 3 (guardrail) or 1 (parse error).
			return verdictResult(result), nil
		}
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		return failureResult("blocktack validate-target", result, err), nil
	}
	if result == nil || len(result.Stdout) == 0 {
		return errorResult("blocktack validate-target produced no verdict"), nil
	}
	return verdictResult(result), nil
}

// verdictResult renders a validate-target verdict, flagging invalid
// verdicts prominently so callers treat them as hard stops.
func verdictResult(result *executor.Result) *mcp.ToolResult {
	payload := json.RawMessage(strings.TrimSpace(string(result.Stdout)))
	var verdict struct {
		Valid      bool     `json:"valid"`
		Name       string   `json:"name"`
		Guardrail  string   `json:"guardrail"`
		Violations []string `json:"violations"`
		Chain      struct {
			Type    string `json:"type"`
			Network string `json:"network"`
		} `json:"chain"`
	}
	header := "## BlockTack Target Validation"
	summary := ""
	if err := json.Unmarshal(payload, &verdict); err == nil {
		if verdict.Valid {
			summary = "- **Status:** VALID — target is runnable in safe mode"
		} else {
			summary = "- **Status:** INVALID (hard stop; do not retry without fixing the target file)"
		}
		if verdict.Name != "" || verdict.Chain.Type != "" {
			summary += "\n- **Target:** " + strings.TrimSpace(verdict.Name+" "+verdict.Chain.Type+" "+verdict.Chain.Network)
		}
		if verdict.Guardrail != "" {
			summary += "\n- **Guardrail:** " + verdict.Guardrail
		}
		if len(verdict.Violations) > 0 {
			summary += "\n- **Violations:** " + strings.Join(verdict.Violations, "; ")
		}
	}
	return jsonResult(header, summary, payload)
}
