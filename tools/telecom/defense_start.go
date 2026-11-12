package telecom

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// defenseBinary is the allowlist name of the StaticZero defense daemon.
const defenseBinary = "staticzero-defense"

// maxCorrelationWindow bounds --correlation-window (24h in seconds).
const maxCorrelationWindow = 86400

// defenseGroupFlags maps the group parameter to the corresponding daemon CLI
// flag. The empty group defaults to telecom-detect.
var defenseGroupFlags = map[string]string{
	"all":                "--all",
	"telecom-detect":     "--telecom-detect",
	"telecom-advanced":   "--telecom-advanced",
	"telecom-5g-defense": "--telecom-5g-defense",
	"satellite-defense":  "--satellite-defense",
	"rf-defense":         "--rf-defense",
}

// DefenseStartTool starts the StaticZero defense daemon
// (staticzero-defense) as a managed background process via the
// BackgroundManager, which enforces the same binary allowlist and argument
// validation as the regular executor.
type DefenseStartTool struct {
	mgr *executor.BackgroundManager
}

// NewDefenseStart constructs the telecom_defense_start tool.
func NewDefenseStart(mgr *executor.BackgroundManager) *DefenseStartTool {
	return &DefenseStartTool{mgr: mgr}
}

func (t *DefenseStartTool) Name() string { return "telecom_defense_start" }

func (t *DefenseStartTool) Description() string {
	return "Start the StaticZero defense engine daemon (staticzero-defense) as a managed background process with a detection module group (telecom-detect default, or telecom-advanced / telecom-5g-defense / satellite-defense / rf-defense / all), optional explicit module IDs, config file, and correlation window. SIEM JSON-lines alerts stream to <logs_dir>/staticzero-defense-<id>.jsonl (--json); logs go to <logs_dir>/staticzero-defense-<id>.err. Wraps StaticZero (eBPF telecom security research); authorized lab use only. Requires root and kernel >= 5.15 (BPF); high-impact: runs a privileged eBPF detection daemon until telecom_defense_stop is called. Startup failures (missing privileges, unsupported kernel) are written to the stderr log; use telecom_defense_status to check whether the daemon survived startup."
}

func (t *DefenseStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"modules": {
				"type": "string",
				"description": "Explicit module IDs for the --modules flag (e.g. \"16,17,24\"); overrides group selection"
			},
			"group": {
				"type": "string",
				"enum": ["all", "telecom-detect", "telecom-advanced", "telecom-5g-defense", "satellite-defense", "rf-defense"],
				"description": "Detection module group (default: telecom-detect)"
			},
			"config": {
				"type": "string",
				"description": "Path to an existing config file (default: /etc/staticzero/config.toml)"
			},
			"correlation_window": {
				"type": "integer",
				"minimum": 1,
				"maximum": 86400,
				"description": "Correlation window in seconds for the --correlation-window flag"
			},
			"logs_dir": {
				"type": "string",
				"description": "Required directory for daemon output files; created with 0700 if missing. SIEM JSON-lines alerts and logs are written here"
			}
		},
		"required": ["logs_dir"]
	}`)
}

func (t *DefenseStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Modules           string `json:"modules"`
		Group             string `json:"group"`
		Config            string `json:"config"`
		CorrelationWindow *int   `json:"correlation_window"`
		LogsDir           string `json:"logs_dir"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Group == "" {
		input.Group = "telecom-detect"
	}
	groupFlag, ok := defenseGroupFlags[input.Group]
	if !ok {
		return errorResult(fmt.Sprintf("invalid group %q: must be all, telecom-detect, telecom-advanced, telecom-5g-defense, satellite-defense or rf-defense", input.Group)), nil
	}
	if err := validateSafeString(input.Modules, "modules"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Config != "" {
		if err := validateInputFile(input.Config, "config"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.CorrelationWindow != nil {
		if *input.CorrelationWindow < 1 || *input.CorrelationWindow > maxCorrelationWindow {
			return errorResult(fmt.Sprintf("correlation_window must be 1-%d seconds", maxCorrelationWindow)), nil
		}
	}
	if err := validateOutputDir(input.LogsDir, "logs_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{groupFlag, "--json"}
	if input.Modules != "" {
		args = append(args, "--modules", input.Modules)
	}
	if input.Config != "" {
		args = append(args, "--config", input.Config)
	}
	if input.CorrelationWindow != nil {
		args = append(args, "--correlation-window", strconv.Itoa(*input.CorrelationWindow))
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := defenseRandomSuffix()
	stdoutPath := filepath.Join(input.LogsDir, "staticzero-defense-"+suffix+".jsonl")
	stderrPath := filepath.Join(input.LogsDir, "staticzero-defense-"+suffix+".err")

	proc, err := t.mgr.Start(ctx, defenseBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + defenseBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## StaticZero Defense Daemon Started\n\n")
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", defenseBinary)
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", defenseBinary, strings.Join(args, " "))
	fmt.Fprintf(&sb, "- **Module group:** %s (%s)\n", input.Group, groupFlag)
	fmt.Fprintf(&sb, "- **SIEM alerts (JSON lines):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `telecom_defense_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `telecom_defense_status` with process_id `%s` reports live state\n", proc.ID)
	sb.WriteString("- The daemon requires root and kernel >= 5.15; if it exits immediately, its stderr log (start failure reason) explains why.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// defenseRandomSuffix returns 8 hex chars used to name per-process output
// files. It is generated before Start because Start requires the output
// paths up front.
func defenseRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
