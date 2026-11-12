package msf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// moduleRunModes maps the run_mode parameter to its console command.
var moduleRunModes = map[string]string{
	"run":         "run",
	"exploit":     "exploit",
	"exploit-job": "exploit -j",
}

// ModuleRunTool runs Metasploit exploit/auxiliary/post modules by driving
// msfconsole with a generated resource file.
type ModuleRunTool struct {
	exec executor.Executor
}

// NewModuleRun creates the module execution tool.
func NewModuleRun(exec executor.Executor) *ModuleRunTool {
	return &ModuleRunTool{exec: exec}
}

func (t *ModuleRunTool) Name() string { return "msf_module_run" }

func (t *ModuleRunTool) Description() string {
	return "Run a Metasploit exploit, auxiliary or post module against a target: writes a resource file into the " +
		"required work_dir (use <module>, sorted set lines for module options, sorted setg lines for global " +
		"options, the run command, exit) and executes msfconsole -q -r on it. run_mode 'run' suits auxiliary and " +
		"post modules, 'exploit' fires exploit modules (e.g. exploit/multi/handler as a listener, " +
		"exploit/windows/smb/ms17_010_eternalblue), and 'exploit-job' backgrounds the exploit as a job (-j) so " +
		"the console returns immediately-ish. HIGH IMPACT: this launches exploits against target systems - " +
		"authorized engagements only; when an engagement is active, targets (RHOSTS/RHOST) are scope-checked by " +
		"the engagement middleware; approval-gated. Note: msfconsole startup is slow (10-60 seconds) and runtime " +
		"is bounded by the REDHANDS_TIMEOUT setting."
}

func (t *ModuleRunTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"module": {
				"type": "string",
				"pattern": "^(exploit|auxiliary|post)/[a-z0-9/_.+-]+$",
				"description": "Full module reference, e.g. exploit/multi/handler, auxiliary/scanner/portscan/tcp, post/multi/manage/shell_to_meterpreter"
			},
			"options": {
				"type": "object",
				"additionalProperties": {"type": "string"},
				"description": "Module datastore options written as set KEY VALUE lines (RHOSTS, RHOST, LHOST, LPORT, ...); keys must match ^[A-Za-z][A-Za-z0-9_]*$"
			},
			"global_options": {
				"type": "object",
				"additionalProperties": {"type": "string"},
				"description": "Global datastore options written as setg KEY VALUE lines (persist for the whole console session)"
			},
			"run_mode": {
				"type": "string",
				"enum": ["run", "exploit", "exploit-job"],
				"description": "How to launch the module: run for auxiliary/post modules (default), exploit for exploit modules, exploit-job to background the exploit as a job"
			},
			"work_dir": {
				"type": "string",
				"description": "Required working directory (created with 0700 if missing) where the generated resource file lands and is kept for audit"
			}
		},
		"required": ["module", "work_dir"]
	}`)
}

type moduleRunInput struct {
	Module        string            `json:"module"`
	Options       map[string]string `json:"options"`
	GlobalOptions map[string]string `json:"global_options"`
	RunMode       string            `json:"run_mode"`
	WorkDir       string            `json:"work_dir"`
}

func (t *ModuleRunTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input moduleRunInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}

	if err := validateRunnableModule(input.Module, "module"); err != nil {
		return errorResult(err.Error()), nil
	}
	optionKeys, err := validateOptionMap(input.Options, "options")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	globalKeys, err := validateOptionMap(input.GlobalOptions, "global_options")
	if err != nil {
		return errorResult(err.Error()), nil
	}
	runMode := input.RunMode
	if runMode == "" {
		runMode = "run"
	}
	runCommand, ok := moduleRunModes[runMode]
	if !ok {
		return errorResult(fmt.Sprintf("invalid run_mode %q: must be run, exploit or exploit-job", runMode)), nil
	}
	if err := validateWorkDir(input.WorkDir); err != nil {
		return errorResult(err.Error()), nil
	}

	// The resource file content is assembled only from validated structured
	// parameters (sorted for determinism), so no arbitrary console commands
	// can be injected and repeated runs produce identical scripts.
	commands := []string{"use " + input.Module}
	for _, k := range optionKeys {
		commands = append(commands, "set "+k+" "+input.Options[k])
	}
	for _, k := range globalKeys {
		commands = append(commands, "setg "+k+" "+input.GlobalOptions[k])
	}
	commands = append(commands, runCommand)

	rcPath, err := writeResourceFile(input.WorkDir, "run", commands)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	result, err := t.exec.Run(ctx, "msfconsole", "-q", "-r", rcPath)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("msfconsole failed: %v\n%s", err, stderr)), nil
	}

	var sb strings.Builder
	sb.WriteString("## Metasploit Module Run\n\n")
	fmt.Fprintf(&sb, "**Module**: %s\n", input.Module)
	fmt.Fprintf(&sb, "**Run mode**: %s\n", runMode)
	fmt.Fprintf(&sb, "**Resource file**: %s (kept for audit)\n\n", rcPath)
	sb.WriteString("```\n")
	if out := strings.TrimSpace(string(result.Stdout)); out != "" {
		sb.WriteString(out + "\n")
	} else {
		sb.WriteString("(no output)\n")
	}
	sb.WriteString("```\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
