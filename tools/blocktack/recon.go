package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// targetScopedInput is the shared parameter shape for target-taking
// tools: the target YAML path, an optional findings output file, and the
// optional endpoint URL list for engagement-scope checking by callers.
type targetScopedInput struct {
	Target  string   `json:"target"`
	Out     string   `json:"out"`
	Targets []string `json:"targets"`
}

// validateTargetScoped validates the shared target-taking parameters.
func validateTargetScoped(input *targetScopedInput) error {
	if err := validateInputFile(input.Target, "target"); err != nil {
		return err
	}
	if input.Out != "" {
		if err := validateOutputFile(input.Out, "out"); err != nil {
			return err
		}
	}
	for _, u := range input.Targets {
		if err := validateSafeString(u, "targets entry"); err != nil {
			return err
		}
	}
	return nil
}

// emitArgs appends the output-mode flags: with out set, findings JSON is
// written to the file (and the tool reports the path); otherwise the
// native findings array goes to stdout via --emit findings-json.
func emitArgs(args []string, out string) []string {
	if out != "" {
		return append(args, "--out", out)
	}
	return append(args, "--emit", "findings-json")
}

// runFindingsCommand executes a findings-producing BlockTack command and
// renders its findings (stdout or --out file).
func runFindingsCommand(ctx context.Context, exec executor.Executor, header, command string, args []string, out string) (*mcp.ToolResult, error) {
	result, err := runCLI(ctx, exec, append([]string{command}, args...)...)
	if err != nil {
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		return failureResult("blocktack "+command, result, err), nil
	}
	if out != "" {
		data, readErr := readFileIfExists(out)
		if readErr != nil {
			return errorResult(fmt.Sprintf("blocktack %s did not produce a readable findings file at %s: %v", command, out, readErr)), nil
		}
		res := findingsToolResult(header, data)
		res.Content[0].Text += "\n- **Findings file:** `" + out + "`\n"
		return res, nil
	}
	if result == nil || len(strings.TrimSpace(string(result.Stdout))) == 0 {
		return errorResult("blocktack " + command + " produced no findings output"), nil
	}
	return findingsToolResult(header, result.Stdout), nil
}

// ReconTool runs `blocktack recon`: L0/L1 endpoint probing (RPC exposure,
// node fingerprinting) against safe-mode-confined endpoints.
type ReconTool struct {
	exec executor.Executor
}

// NewRecon constructs the blocktack_recon tool.
func NewRecon(exec executor.Executor) *ReconTool {
	return &ReconTool{exec: exec}
}

func (t *ReconTool) Name() string { return "blocktack_recon" }

func (t *ReconTool) Description() string {
	return "Run BlockTack reconnaissance (blocktack recon) against a validated target: probes the target's RPC endpoints for L0/L1 infrastructure and node weaknesses (exposure, client fingerprinting, configuration). Safe mode is enforced inside the binary — endpoints must be loopback or listed in the target's authorization.liveTargets. Call blocktack_validate_target first. Findings are returned as a JSON array (fenced, with severity summary); pass out to write them to a file instead for large outputs." + authorizedUseNotice
}

func (t *ReconTool) InputSchema() json.RawMessage {
	return targetScopedSchema("Probe the target's endpoints for L0/L1 weaknesses (seconds, network I/O against the target's loopback/allow-listed endpoints)")
}

func (t *ReconTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input targetScopedInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateTargetScoped(&input); err != nil {
		return errorResult(err.Error()), nil
	}
	args := emitArgs([]string{"--target", input.Target}, input.Out)
	return runFindingsCommand(ctx, t.exec, "## BlockTack Recon", "recon", args, input.Out)
}

// ScanTool runs `blocktack scan`: static analysis adapters (Slither,
// Foundry) over the target's contracts.
type ScanTool struct {
	exec executor.Executor
}

// NewScan constructs the blocktack_scan tool.
func NewScan(exec executor.Executor) *ScanTool {
	return &ScanTool{exec: exec}
}

func (t *ScanTool) Name() string { return "blocktack_scan" }

func (t *ScanTool) Description() string {
	return "Run BlockTack contract analysis adapters (blocktack scan) against a validated target: static analysis via the slither adapter (needs slither-analyzer installed) and PoC execution via the foundry adapter (needs forge; passing test_poc_* tests count as confirmed findings). Local analysis in a self-cleaning temp directory; seconds to minutes depending on contract size. Adapters are validated against the registry (see blocktack_capabilities). Findings are returned as a JSON array; pass out to write them to a file instead." + authorizedUseNotice
}

func (t *ScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the BlockTack target YAML"
			},
			"adapters": {
				"type": "array",
				"items": {"type": "string", "enum": ["slither", "foundry"]},
				"maxItems": 2,
				"description": "Analysis adapters to run (default: slither)"
			},
			"out": {
				"type": "string",
				"description": "Optional file path to write the findings JSON array to (for large scans); the tool then reports the path instead of inline findings"
			},
			"targets": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional list of the target's endpoint URLs; supplied so engagement scope checks can verify network targets"
			}
		},
		"required": ["target"]
	}`)
}

func (t *ScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		targetScopedInput
		Adapters []string `json:"adapters"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateTargetScoped(&input.targetScopedInput); err != nil {
		return errorResult(err.Error()), nil
	}

	seen := make(map[string]bool, len(input.Adapters))
	adapters := make([]string, 0, len(input.Adapters))
	for _, a := range input.Adapters {
		if a != "slither" && a != "foundry" {
			return errorResult(fmt.Sprintf("invalid adapter %q: must be slither or foundry", a)), nil
		}
		if !seen[a] {
			seen[a] = true
			adapters = append(adapters, a)
		}
	}

	args := []string{"--target", input.Target}
	if len(adapters) > 0 {
		args = append(args, "--adapters", joinComma(adapters))
	}
	args = emitArgs(args, input.Out)
	return runFindingsCommand(ctx, t.exec, "## BlockTack Scan", "scan", args, input.Out)
}

// NodeAuditTool runs `blocktack node-audit`: L0/L1 node attack-surface
// modules against the target's RPC endpoints.
type NodeAuditTool struct {
	exec executor.Executor
}

// NewNodeAudit constructs the blocktack_node_audit tool.
func NewNodeAudit(exec executor.Executor) *NodeAuditTool {
	return &NodeAuditTool{exec: exec}
}

func (t *NodeAuditTool) Name() string { return "blocktack_node_audit" }

func (t *NodeAuditTool) Description() string {
	return "Run a BlockTack node attack-surface audit module (blocktack node-audit) against a validated target: cve-check (client CVE cross-reference; downloads an advisory cache), rpc-fuzz (malformed RPC input for DoS detection), mempool-analysis, peer-analysis, web-audit, or p2p-eclipse, or all. Read-only or deliberately malformed input only; nothing is broadcast. Safe mode is enforced inside the binary. Findings are returned as a JSON array; pass out to write them to a file instead." + authorizedUseNotice
}

func (t *NodeAuditTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the BlockTack target YAML"
			},
			"module": {
				"type": "string",
				"enum": ["all", "cve-check", "rpc-fuzz", "mempool-analysis", "peer-analysis", "web-audit", "p2p-eclipse"],
				"description": "Audit module to run (default: all)"
			},
			"out": {
				"type": "string",
				"description": "Optional file path to write the findings JSON array to; the tool then reports the path instead of inline findings"
			},
			"targets": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional list of the target's endpoint URLs; supplied so engagement scope checks can verify network targets"
			}
		},
		"required": ["target"]
	}`)
}

func (t *NodeAuditTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		targetScopedInput
		Module string `json:"module"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateTargetScoped(&input.targetScopedInput); err != nil {
		return errorResult(err.Error()), nil
	}

	module := input.Module
	if module == "" {
		module = "all"
	}
	switch module {
	case "all", "cve-check", "rpc-fuzz", "mempool-analysis", "peer-analysis", "web-audit", "p2p-eclipse":
	default:
		return errorResult(fmt.Sprintf("invalid module %q: must be all, cve-check, rpc-fuzz, mempool-analysis, peer-analysis, web-audit or p2p-eclipse", module)), nil
	}

	args := []string{"--target", input.Target, "--module", module}
	args = emitArgs(args, input.Out)
	return runFindingsCommand(ctx, t.exec, "## BlockTack Node Audit ("+module+")", "node-audit", args, input.Out)
}

// targetScopedSchema builds the common recon-style schema.
func targetScopedSchema(outDescription string) json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the BlockTack target YAML (must carry a valid authorization block; call blocktack_validate_target first)"
			},
			"out": {
				"type": "string",
				"description": "` + outDescription + `"
			},
			"targets": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional list of the target's endpoint URLs; supplied so engagement scope checks can verify network targets"
			}
		},
		"required": ["target"]
	}`)
}

// joinComma joins validated adapter names for the --adapters flag.
func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// readFileIfExists reads a file the wrapped CLI was asked to write, so
// tool output includes the findings, not just a path.
func readFileIfExists(path string) ([]byte, error) {
	return os.ReadFile(path)
}
