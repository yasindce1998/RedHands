package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// engineActions lists the actions each Rust engine implements (mirrors the
// dispatch tables in engine-evm/src/main.rs and engine-solana/src/main.rs).
var engineActions = map[string]map[string]bool{
	evmEngineBinary: {
		"fingerprint": true, "map-oracles": true, "verify-pnl": true,
		"simulate-tx-sequence": true, "erc20-balance": true,
		"simulate-call": true, "hook-audit": true, "oracle-staleness": true,
	},
	solanaEngineBinary: {
		"fingerprint": true, "balance": true,
	},
}

// engineJob is the stdin contract shared by both engines:
// {"action": "...", "options": {...}, "target": {...}}.
type engineJob struct {
	Action  string          `json:"action"`
	Options json.RawMessage `json:"options,omitempty"`
	Target  engineTarget    `json:"target"`
}

type engineTarget struct {
	Name      string           `json:"name,omitempty"`
	Endpoints []engineEndpoint `json:"endpoints"`
	Contracts []engineContract `json:"contracts,omitempty"`
}

type engineEndpoint struct {
	Role string `json:"role,omitempty"`
	URL  string `json:"url"`
}

type engineContract struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

// EngineCallTool drives a BlockTack Rust engine directly: a JSON job is
// piped to the engine's stdin and a findings JSON array comes back on
// stdout. The engines do not run BlockTack's own safe-mode check, so this
// wrapper confines rpc_url to loopback hosts; live targets must go through
// a target file and blocktack_campaign_start instead.
type EngineCallTool struct {
	exec executor.Executor
}

// NewEngineCall constructs the blocktack_engine_call tool.
func NewEngineCall(exec executor.Executor) *EngineCallTool {
	return &EngineCallTool{exec: exec}
}

func (t *EngineCallTool) Name() string { return "blocktack_engine_call" }

func (t *EngineCallTool) Description() string {
	return "Invoke a BlockTack Rust engine directly (stdin JSON job, stdout findings JSON array): engine blocktack-evm actions fingerprint, map-oracles, verify-pnl, simulate-tx-sequence (zero-footprint revm simulation), erc20-balance, simulate-call (state-override eth_call), hook-audit (Uniswap v4), oracle-staleness; engine blocktack-solana actions fingerprint, balance. Safety: the engines bypass BlockTack's target-file guardrails, so this wrapper only accepts loopback rpc_url values (local anvil forks, fixtures) — for authorized live targets use a target YAML with an authorization block plus blocktack_campaign_start. Options are passed through to the action unchanged (for example feeds and maxStalenessSeconds for oracle-staleness, to and data for simulate-call)." + authorizedUseNotice
}

func (t *EngineCallTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"engine": {
				"type": "string",
				"enum": ["blocktack-evm", "blocktack-solana"],
				"description": "Engine binary to invoke"
			},
			"action": {
				"type": "string",
				"description": "Engine action (blocktack-evm: fingerprint, map-oracles, verify-pnl, simulate-tx-sequence, erc20-balance, simulate-call, hook-audit, oracle-staleness; blocktack-solana: fingerprint, balance)"
			},
			"options": {
				"type": "object",
				"description": "Action options passed through to the engine verbatim"
			},
			"rpc_url": {
				"type": "string",
				"description": "RPC endpoint URL for the engine job (must be a loopback host, e.g. http://127.0.0.1:8545)"
			},
			"contracts": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"name": {"type": "string"},
						"address": {"type": "string"}
					}
				},
				"maxItems": 32,
				"description": "Optional contract list for the job target (name + address)"
			}
		},
		"required": ["engine", "action", "rpc_url"]
	}`)
}

func (t *EngineCallTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Engine    string           `json:"engine"`
		Action    string           `json:"action"`
		Options   json.RawMessage  `json:"options"`
		RpcURL    string           `json:"rpc_url"`
		Contracts []engineContract `json:"contracts"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	actions, ok := engineActions[input.Engine]
	if !ok {
		return errorResult(fmt.Sprintf("invalid engine %q: must be blocktack-evm or blocktack-solana", input.Engine)), nil
	}
	if !actions[input.Action] {
		return errorResult(fmt.Sprintf("invalid action %q for %s; supported: %s", input.Action, input.Engine, strings.Join(sortedKeys(actions), ", "))), nil
	}
	// The engine safety contract lives here, not in the engine: loopback
	// only, no escape hatch.
	if err := validateLoopbackURL(input.RpcURL); err != nil {
		return errorResult(err.Error()), nil
	}
	if len(input.Contracts) > 32 {
		return errorResult("contracts accepts at most 32 entries"), nil
	}
	for _, c := range input.Contracts {
		if err := validateSafeString(c.Name, "contracts name"); err != nil {
			return errorResult(err.Error()), nil
		}
		if err := validateSafeString(c.Address, "contracts address"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	options := input.Options
	if len(options) == 0 {
		options = json.RawMessage("{}")
	}
	if err := json.Unmarshal(options, &map[string]any{}); err != nil {
		return errorResult("options must be a JSON object"), nil
	}

	job := engineJob{
		Action:  input.Action,
		Options: options,
		Target: engineTarget{
			Endpoints: []engineEndpoint{{Role: "rpc", URL: input.RpcURL}},
			Contracts: input.Contracts,
		},
	}
	stdin, err := json.Marshal(job)
	if err != nil {
		return errorResult("could not encode engine job: " + err.Error()), nil
	}

	// Engines take no CLI arguments; the whole job travels on stdin, so
	// the executor's argument metacharacter validation is not a factor.
	result, err := runBinaryStdin(ctx, t.exec, stdin, input.Engine)
	if err != nil {
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		stderr := ""
		if result != nil {
			stderr = strings.TrimSpace(string(result.Stderr))
		}
		return errorResult(fmt.Sprintf("%s failed: %s\n%s", input.Engine, err.Error(), stderr)), nil
	}
	if result == nil || len(strings.TrimSpace(string(result.Stdout))) == 0 {
		return errorResult(input.Engine + " produced no findings output"), nil
	}
	header := "## BlockTack Engine Call (" + input.Engine + " " + input.Action + ")"
	return findingsToolResult(header, result.Stdout), nil
}

// sortedKeys returns the sorted action names for error messages.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small fixed sets; simple insertion sort keeps output deterministic.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
