package blocktack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// CampaignStartTool launches a BlockTack playbook campaign as a managed
// background process. The campaign outlives the RPC request; progress is
// streamed as JSON lines to the process's stdout file (crash-resilient
// status.json lands inside the run directory after every step).
type CampaignStartTool struct {
	mgr  *executor.BackgroundManager
	exec executor.Executor
}

// NewCampaignStart constructs the blocktack_campaign_start tool. exec is
// used for the pre-flight target validation that gates the launch.
func NewCampaignStart(mgr *executor.BackgroundManager, exec executor.Executor) *CampaignStartTool {
	return &CampaignStartTool{mgr: mgr, exec: exec}
}

func (t *CampaignStartTool) Name() string { return "blocktack_campaign_start" }

func (t *CampaignStartTool) Description() string {
	return "Start a BlockTack blockchain adversary-simulation campaign (playbook execution: engine steps, adapters, shell setup such as anvil forks) as a managed background process. Returns immediately with process_id; poll blocktack_campaign_status for JSON-lines step progress and blocktack_campaign_results for findings/kill chains. Safe mode only — the tool never passes --unsafe, refuses to launch unless the target passes blocktack validate-target (unexpired authorization block; loopback or authorization.liveTargets endpoints), and the binary re-checks guardrails before every step. Playbook and target files are operator-authored artifacts (playbook shell steps run real commands, like anvil forks); only run playbooks from a reviewed source. Only one BlockTack campaign may run at a time (playbooks bind fixed anvil ports). The target's authorization block is the record of permission." + authorizedUseNotice
}

func (t *CampaignStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Path to the BlockTack target YAML (must carry a valid authorization block)"
			},
			"playbook": {
				"type": "string",
				"description": "Path to the playbook YAML (for example the playbooks shipped in the BlockTack release tree)"
			},
			"out_dir": {
				"type": "string",
				"description": "Required directory for campaign output and process logs; created with 0700 if missing. Run artifacts (findings.json, findings.sarif, killchains.json, status.json, campaign.log) land in a timestamped subdirectory"
			},
			"targets": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Optional list of the target's endpoint URLs; supplied so engagement scope checks can verify network targets"
			}
		},
		"required": ["target", "playbook", "out_dir"]
	}`)
}

func (t *CampaignStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Target   string   `json:"target"`
		Playbook string   `json:"playbook"`
		OutDir   string   `json:"out_dir"`
		Targets  []string `json:"targets"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateInputFile(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateInputFile(input.Playbook, "playbook"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateOutputDir(input.OutDir, "out_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	for _, u := range input.Targets {
		if err := validateSafeString(u, "targets entry"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	// Port-collision guard: playbooks hard-code anvil's RPC port, so a
	// second concurrent campaign would race for it.
	for _, st := range t.mgr.List() {
		if st.Binary == blocktackBinary && st.Running {
			return errorResult(fmt.Sprintf(
				"blocktack campaign %s is still running; wait for it or poll blocktack_campaign_status (playbooks bind fixed anvil ports, so campaigns cannot run concurrently)", st.ID)), nil
		}
	}

	// Pre-flight: refuse to launch unless the target validates in safe
	// mode. BlockTack re-checks inside the runner, but failing here is
	// cheaper than a daemon that exits immediately with exit code 3.
	if t.exec != nil {
		result, err := runCLI(ctx, t.exec, "validate-target", "--target", input.Target)
		if err != nil || result == nil || !jsonValidVerdict(result.Stdout) {
			if guardrailRefusal(result, err) {
				return refusalResult(result), nil
			}
			return errorResult("refusing to start: the target does not pass blocktack validate-target (fix the target file; an invalid or expired authorization is a hard stop)"), nil
		}
	}

	// Safe mode is not parameterizable here by design: no --unsafe
	// argument is ever emitted.
	suffix := campaignRandomSuffix()
	stdoutPath := filepath.Join(input.OutDir, "campaign-"+suffix+".out")
	stderrPath := filepath.Join(input.OutDir, "campaign-"+suffix+".err")

	args := []string{
		"campaign",
		"--target", input.Target,
		"--playbook", input.Playbook,
		"--out-dir", input.OutDir,
		"--progress-json",
	}
	proc, err := t.mgr.StartEnv(ctx, childEnv(), blocktackBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + blocktackBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## BlockTack Campaign Started\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for status/results chaining.
	daemonJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      blocktackBinary,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", daemonJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", blocktackBinary, strings.Join(args, " "))
	fmt.Fprintf(&sb, "- **JSON-lines progress:** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Human log (stderr):** %s\n", stderrPath)
	fmt.Fprintf(&sb, "- **Run artifacts base:** %s (timestamped subdirectory per run)\n", input.OutDir)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `blocktack_campaign_status` with process_id `%s` reports live step progress\n", proc.ID)
	sb.WriteString("- `blocktack_campaign_results` fetches findings.json / killchains.json from the run directory once finished\n")
	sb.WriteString("- Safe mode only; the target's authorization block is enforced by blocktack itself.\n")

	return &mcp.ToolResult{
		Content:           []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
		StructuredContent: daemonJSON,
	}, nil
}

// jsonValidVerdict reports whether a validate-target stdout verdict says
// the target is valid.
func jsonValidVerdict(stdout []byte) bool {
	var verdict struct {
		Valid bool `json:"valid"`
	}
	return json.Unmarshal(stdout, &verdict) == nil && verdict.Valid
}

// campaignRandomSuffix returns 8 hex chars used to name per-process output
// files, generated before Start because Start needs the paths up front.
func campaignRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
