package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// DoctorTool runs `staticzero-defense --doctor --json`: a read-only platform,
// privilege, ELF, and attachment preflight that prints a DoctorReport and
// exits (defense/src/main.rs returns immediately after preflight when --doctor
// is set; no probes are loaded and no privileges are changed).
type DoctorTool struct {
	exec executor.Executor
}

func NewDoctor(exec executor.Executor) *DoctorTool {
	return &DoctorTool{exec: exec}
}

func (t *DoctorTool) Name() string { return "telecom_doctor" }

func (t *DoctorTool) Description() string {
	return "Run the StaticZero defense engine read-only preflight (staticzero-defense --doctor --json): checks platform, kernel version, BPF capabilities, tracepoint layout, and eBPF object/module availability, then exits without loading probes. A failed preflight is reported in the output rather than as a tool error, because the DoctorReport is the result." + authorizedUseNotice
}

func (t *DoctorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"bpf_path": {
				"type": "string",
				"description": "Path to the compiled eBPF object file (defaults to the staticzero-defense default)"
			},
			"config": {
				"type": "string",
				"description": "Configuration file path (informational for doctor; defaults to /etc/staticzero/config.toml)"
			},
			"modem_path": {
				"type": "string",
				"description": "Exact absolute pathname to observe in openat attempts (defaults to /dev/cdc-wdm0)"
			},
			"modules": {
				"type": "array",
				"items": {"type": "integer", "minimum": 0, "maximum": 255},
				"description": "Select modules explicitly by ID (overrides group flags)"
			},
			"allow_modem_pid": {
				"type": "array",
				"items": {"type": "integer", "minimum": 1, "maximum": 4294967295},
				"maxItems": 32,
				"description": "Authorized process IDs for the modem-path module (at most 32, all nonzero)"
			},
			"all": {
				"type": "boolean",
				"description": "Enable all detection module groups"
			},
			"telecom_detect": {
				"type": "boolean",
				"description": "Enable basic telecom detection modules 16-23 (the binary default is true)"
			},
			"telecom_advanced": {
				"type": "boolean",
				"description": "Enable advanced telecom detection modules 24-28"
			},
			"telecom_5g_defense": {
				"type": "boolean",
				"description": "Enable 5G core defense modules 29-32"
			},
			"satellite_defense": {
				"type": "boolean",
				"description": "Enable satellite defense modules 33-39"
			},
			"rf_defense": {
				"type": "boolean",
				"description": "Enable RF protocol domain defense modules 40-55"
			}
		}
	}`)
}

type doctorInput struct {
	BpfPath          string  `json:"bpf_path,omitempty"`
	Config           string  `json:"config,omitempty"`
	ModemPath        string  `json:"modem_path,omitempty"`
	Modules          []int   `json:"modules,omitempty"`
	AllowModemPID    []int64 `json:"allow_modem_pid,omitempty"`
	All              bool    `json:"all,omitempty"`
	TelecomDetect    *bool   `json:"telecom_detect,omitempty"`
	TelecomAdvanced  bool    `json:"telecom_advanced,omitempty"`
	Telecom5GDefense bool    `json:"telecom_5g_defense,omitempty"`
	SatelliteDefense bool    `json:"satellite_defense,omitempty"`
	RfDefense        bool    `json:"rf_defense,omitempty"`
}

func (t *DoctorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input doctorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validatePath(input.BpfPath, "bpf_path"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.Config, "config"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validatePath(input.ModemPath, "modem_path"); err != nil {
		return errorResult(err.Error()), nil
	}

	if len(input.Modules) > 255 {
		return errorResult("modules list too long (max 255 IDs)"), nil
	}
	for _, m := range input.Modules {
		if m < 0 || m > 255 {
			return errorResult("module IDs must be integers between 0 and 255"), nil
		}
	}
	if len(input.AllowModemPID) > 32 {
		return errorResult("allow_modem_pid accepts at most 32 PIDs"), nil
	}
	for _, pid := range input.AllowModemPID {
		if pid < 1 || pid > 4294967295 {
			return errorResult("allow_modem_pid entries must be nonzero u32 values"), nil
		}
	}

	args := []string{"--doctor", "--json"}
	if input.BpfPath != "" {
		args = append(args, "--bpf-path", input.BpfPath)
	}
	if input.Config != "" {
		args = append(args, "--config", input.Config)
	}
	if input.ModemPath != "" {
		args = append(args, "--modem-path", input.ModemPath)
	}
	if len(input.Modules) > 0 {
		parts := make([]string, 0, len(input.Modules))
		for _, m := range input.Modules {
			parts = append(parts, strconv.Itoa(m))
		}
		args = append(args, "--modules", strings.Join(parts, ","))
	}
	if len(input.AllowModemPID) > 0 {
		parts := make([]string, 0, len(input.AllowModemPID))
		for _, pid := range input.AllowModemPID {
			parts = append(parts, strconv.FormatInt(pid, 10))
		}
		args = append(args, "--allow-modem-pid", strings.Join(parts, ","))
	}
	if input.All {
		args = append(args, "--all")
	}
	if input.TelecomDetect != nil {
		if *input.TelecomDetect {
			args = append(args, "--telecom-detect")
		} else {
			args = append(args, "--telecom-detect=false")
		}
	}
	if input.TelecomAdvanced {
		args = append(args, "--telecom-advanced")
	}
	if input.Telecom5GDefense {
		args = append(args, "--telecom-5g-defense")
	}
	if input.SatelliteDefense {
		args = append(args, "--satellite-defense")
	}
	if input.RfDefense {
		args = append(args, "--rf-defense")
	}

	result, err := t.exec.Run(ctx, "staticzero-defense", args...)

	// staticzero-defense --doctor exits nonzero when the preflight fails,
	// but it has already printed the full DoctorReport JSON on stdout.
	// The report is the answer, so surface it as a normal result.
	if err != nil {
		if result != nil && len(result.Stdout) > 0 {
			return doctorReportResult(string(result.Stdout), string(result.Stderr), false), nil
		}
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("staticzero-defense doctor failed: %s\n%s", err.Error(), stderr)), nil
	}

	if result == nil || len(result.Stdout) == 0 {
		return errorResult("staticzero-defense doctor produced no report output"), nil
	}

	return doctorReportResult(string(result.Stdout), string(result.Stderr), true), nil
}

func doctorReportResult(stdout, stderr string, passed bool) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString("## StaticZero Defense Doctor (read-only preflight)\n\n")
	if passed {
		sb.WriteString("- **Status:** preflight completed\n")
	} else {
		sb.WriteString("- **Status:** PREFLIGHT FAILED (see report below; the engine would refuse to start with this configuration)\n")
	}
	sb.WriteString("- **Binary:** staticzero-defense\n\n")
	sb.WriteString("```json\n")
	sb.WriteString(strings.TrimSpace(stdout))
	sb.WriteString("\n```\n")
	if stderr != "" {
		sb.WriteString("\n<details><summary>stderr</summary>\n\n```\n")
		sb.WriteString(strings.TrimSpace(stderr))
		sb.WriteString("\n```\n\n</details>\n")
	}
	return textResult(sb.String())
}
