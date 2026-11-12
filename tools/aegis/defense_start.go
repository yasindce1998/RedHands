package aegis

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

// defenseBinary is the allowlist name of the Aegis-Shadow defense daemon.
const defenseBinary = "aegis-shadow-defense"

// maxCalibrationPeriod bounds --calibration-period (24h in seconds).
const maxCalibrationPeriod = 86400

// validDefenseModuleNames indexes the 15 per-module detection flag names
// (without the -- prefix) accepted by the modules parameter.
var validDefenseModuleNames = func() map[string]bool {
	names := make(map[string]bool, len(defenseModules))
	for _, mod := range defenseModules {
		names[strings.TrimPrefix(mod.Flag, "--")] = true
	}
	return names
}()

// defenseModuleList renders the valid module names for error messages.
var defenseModuleList = func() string {
	names := make([]string, 0, len(defenseModules))
	for _, mod := range defenseModules {
		names = append(names, strings.TrimPrefix(mod.Flag, "--"))
	}
	return strings.Join(names, ", ")
}()

// DefenseStartTool starts the Aegis-Shadow defense daemon
// (aegis-shadow-defense) as a managed background process via the
// BackgroundManager, which enforces the same binary allowlist and argument
// validation as the regular executor.
type DefenseStartTool struct {
	mgr *executor.BackgroundManager
}

// NewDefenseStart constructs the aegis_defense_start tool.
func NewDefenseStart(mgr *executor.BackgroundManager) *DefenseStartTool {
	return &DefenseStartTool{mgr: mgr}
}

func (t *DefenseStartTool) Name() string { return "aegis_defense_start" }

func (t *DefenseStartTool) Description() string {
	return "Start the Aegis-Shadow defense daemon (aegis-shadow-defense) as a managed background process with selected detection modules (empty list = all 15 modules), alert threshold (1-4), calibration period, runtime config, and optional ML layer. Alerts stream as NDJSON to <alerts_dir>/aegis-defense-<id>.ndjson (--json-stdout); logs go to <alerts_dir>/aegis-defense-<id>.err. Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Requires root/eBPF privileges; high-impact: runs a privileged detection daemon until aegis_defense_stop is called. If the daemon exits immediately (missing privileges), check the stderr log via aegis_defense_status. Use aegis_alerts_parse / aegis_alerts_tail to read the alert stream."
}

func (t *DefenseStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"modules": {
				"type": "array",
				"items": {"type": "string"},
				"maxItems": 15,
				"description": "Detection module flag names without the -- prefix (e.g. ghost-maps, syscall-latency). Empty or omitted enables all 15 modules (--all-modules). Valid names: ghost-maps, syscall-latency, bytecode-check, hidden-process, suspicious-hooks, prog-inventory, syscall-anomaly, net-baseline, memfd-detect, map-audit, tracepoint-monitor, cross-reference, hw-perf-counters, verifier-analysis, memory-forensics"
			},
			"threshold": {
				"type": "integer",
				"minimum": 1,
				"maximum": 4,
				"description": "Minimum alert severity to emit (1=Low, 2=Medium, 3=High, 4=Critical)"
			},
			"calibration_period": {
				"type": "integer",
				"minimum": 1,
				"maximum": 86400,
				"description": "Baseline calibration period in seconds before anomaly detection activates (default 60)"
			},
			"config": {
				"type": "string",
				"description": "Path to an existing runtime config JSON ({\"threshold\":N,\"window_secs\":N}), hot-reloaded every 5s"
			},
			"enable_ml": {
				"type": "boolean",
				"description": "Enable the adversarial ML detection layer (--enable-ml)"
			},
			"alerts_dir": {
				"type": "string",
				"description": "Required directory for daemon output files; created with 0700 if missing. Alerts (NDJSON) and logs are written here"
			}
		},
		"required": ["alerts_dir"]
	}`)
}

func (t *DefenseStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Modules           []string `json:"modules"`
		Threshold         *int     `json:"threshold"`
		CalibrationPeriod *int     `json:"calibration_period"`
		Config            string   `json:"config"`
		EnableML          bool     `json:"enable_ml"`
		AlertsDir         string   `json:"alerts_dir"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	// Validate module names against the exact 15-flag catalog.
	if len(input.Modules) > len(defenseModules) {
		return errorResult(fmt.Sprintf("modules accepts at most %d entries", len(defenseModules))), nil
	}
	seenModules := make(map[string]bool, len(input.Modules))
	modules := make([]string, 0, len(input.Modules))
	for _, mod := range input.Modules {
		if err := validateSafeString(mod, "modules entry"); err != nil {
			return errorResult(err.Error()), nil
		}
		if !validDefenseModuleNames[mod] {
			return errorResult(fmt.Sprintf("unknown defense module %q; valid modules: %s", mod, defenseModuleList)), nil
		}
		if !seenModules[mod] {
			seenModules[mod] = true
			modules = append(modules, mod)
		}
	}

	if input.Threshold != nil {
		if err := validateThreshold(*input.Threshold); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.CalibrationPeriod != nil {
		if *input.CalibrationPeriod < 1 || *input.CalibrationPeriod > maxCalibrationPeriod {
			return errorResult(fmt.Sprintf("calibration_period must be 1-%d seconds", maxCalibrationPeriod)), nil
		}
	}
	if input.Config != "" {
		if err := validateExistingFile(input.Config, "config", maxAlertFileSize); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateOutputDir(input.AlertsDir, "alerts_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := make([]string, 0, len(modules)+8)
	if len(modules) == 0 {
		args = append(args, "--all-modules")
	} else {
		for _, mod := range modules {
			args = append(args, "--"+mod)
		}
	}
	// Alerts always stream as NDJSON on stdout; logs go to stderr.
	args = append(args, "--json-stdout")
	if input.Threshold != nil {
		args = append(args, "-t", strconv.Itoa(*input.Threshold))
	}
	if input.CalibrationPeriod != nil {
		args = append(args, "--calibration-period", strconv.Itoa(*input.CalibrationPeriod))
	}
	if input.Config != "" {
		args = append(args, "--config", input.Config)
	}
	if input.EnableML {
		args = append(args, "--enable-ml")
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := defenseRandomSuffix()
	stdoutPath := filepath.Join(input.AlertsDir, "aegis-defense-"+suffix+".ndjson")
	stderrPath := filepath.Join(input.AlertsDir, "aegis-defense-"+suffix+".err")

	proc, err := t.mgr.Start(ctx, defenseBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + defenseBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Defense Daemon Started\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for stop/status chaining.
	daemonJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      defenseBinary,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", daemonJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", defenseBinary)
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", defenseBinary, strings.Join(args, " "))
	if len(modules) == 0 {
		sb.WriteString("- **Modules:** all 15 (--all-modules)\n")
	} else {
		fmt.Fprintf(&sb, "- **Modules:** %s\n", strings.Join(modules, ", "))
	}
	fmt.Fprintf(&sb, "- **Alerts (NDJSON):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `aegis_alerts_parse` and `aegis_alerts_tail` read the NDJSON alert file at %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- `aegis_defense_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `aegis_defense_status` with process_id `%s` reports live state\n", proc.ID)
	sb.WriteString("- The daemon runs until stopped and requires root/eBPF; if it exits immediately, its stderr log explains why.\n")

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
