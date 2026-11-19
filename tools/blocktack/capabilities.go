package blocktack

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// CapabilitiesTool runs `blocktack capabilities`: the machine-readable
// platform inventory (version, engines probed on disk, adapters, node-audit
// modules, taxonomy summary). Read-only, no target needed.
type CapabilitiesTool struct {
	exec executor.Executor
}

// NewCapabilities constructs the blocktack_capabilities tool.
func NewCapabilities(exec executor.Executor) *CapabilitiesTool {
	return &CapabilitiesTool{exec: exec}
}

func (t *CapabilitiesTool) Name() string { return "blocktack_capabilities" }

func (t *CapabilitiesTool) Description() string {
	return "Query the BlockTack platform inventory (blocktack capabilities): CLI version, presence and paths of the Rust engines (blocktack-evm, blocktack-solana), available analysis adapters (slither, foundry), node-audit modules, and the weakness taxonomy summary. Read-only and target-free; call this first to learn what the local BlockTack installation can drive before planning recon, scans, audits, or campaigns." + authorizedUseNotice
}

func (t *CapabilitiesTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`)
}

func (t *CapabilitiesTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	result, err := runCLI(ctx, t.exec, "capabilities")
	if err != nil {
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		return failureResult("blocktack capabilities", result, err), nil
	}
	if result == nil || len(result.Stdout) == 0 {
		return errorResult("blocktack capabilities produced no output"), nil
	}
	return jsonResult("## BlockTack Capabilities", engineSummary(result.Stdout), json.RawMessage(strings.TrimSpace(string(result.Stdout)))), nil
}

// engineSummary extracts a one-line engine presence summary from a
// capabilities JSON document.
func engineSummary(payload []byte) string {
	var caps struct {
		Version string `json:"version"`
		Root    string `json:"root"`
		Engines []struct {
			Name    string `json:"name"`
			Present bool   `json:"present"`
		} `json:"engines"`
		Adapters []string `json:"adapters"`
	}
	if err := json.Unmarshal(payload, &caps); err != nil {
		return ""
	}
	parts := make([]string, 0, len(caps.Engines)+2)
	for _, e := range caps.Engines {
		state := "missing"
		if e.Present {
			state = "present"
		}
		parts = append(parts, e.Name+" "+state)
	}
	parts = append(parts, "adapters: "+strings.Join(caps.Adapters, ", "))
	return "- **Version:** " + caps.Version + "\n- **Engines:** " + strings.Join(parts, "; ")
}
