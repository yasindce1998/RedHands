package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// offenseBinary is the allowlist name of the StaticZero offense daemon.
const offenseBinary = "staticzero-offense"

// offenseGroupFlags maps the groups parameter entries to the corresponding
// --enable-* CLI flags of the staticzero-offense release binary (v0.5.0).
var offenseGroupFlags = map[string]string{
	"telecom":          "--enable-telecom",
	"telecom-advanced": "--enable-telecom-advanced",
	"5g-advanced":      "--enable-5g-advanced",
	"satellite":        "--enable-satellite",
	"rf":               "--enable-rf",
}

// offenseIfaceRegex accepts plain interface names (letters, digits, dash,
// dot, underscore; Linux IFNAMSIZ bound).
var offenseIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

// offenseIMSIRegex accepts exactly 15 digits (3GPP IMSI format).
var offenseIMSIRegex = regexp.MustCompile(`^[0-9]{15}$`)

// validateOffenseIface enforces a plain interface name without shell
// metacharacters.
func validateOffenseIface(iface, field string) error {
	if err := validateSafeString(iface, field); err != nil {
		return err
	}
	if !offenseIfaceRegex.MatchString(iface) {
		return fmt.Errorf("invalid %s: must be a plain interface name (e.g. gtp0)", field)
	}
	return nil
}

// OffenseStartTool starts the StaticZero telecom exploitation research
// loader (staticzero-offense) as a managed background process via the
// BackgroundManager, which enforces the same binary allowlist and argument
// validation as the regular executor.
type OffenseStartTool struct {
	mgr *executor.BackgroundManager
}

// NewOffenseStart constructs the telecom_offense_start tool.
func NewOffenseStart(mgr *executor.BackgroundManager) *OffenseStartTool {
	return &OffenseStartTool{mgr: mgr}
}

func (t *OffenseStartTool) Name() string { return "telecom_offense_start" }

func (t *OffenseStartTool) Description() string {
	return "Launch the StaticZero telecom exploitation research loader (staticzero-offense, interception features F89-F172) as a managed background process in an authorized lab: one or more feature groups (telecom, telecom-advanced, 5g-advanced, satellite, rf) or all, optional target IMSI, optional BPF object override, and per-domain interfaces. Loader output streams to <logs_dir>/staticzero-offense-<id>.log; logs go to <logs_dir>/staticzero-offense-<id>.err. Telecom interception is regulated in many jurisdictions even in labs — authorized, isolated lab environments only. Wraps StaticZero (eBPF telecom security research); requires root and kernel >= 5.15 (BPF); high-impact: runs a privileged offense daemon until telecom_offense_stop is called. Approval-gated. If the daemon exits immediately (missing privileges, unsupported kernel), check the stderr log via telecom_offense_status."
}

func (t *OffenseStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"logs_dir": {
				"type": "string",
				"description": "Required directory for daemon output files; created with 0700 if missing. Loader output and logs are written here"
			},
			"groups": {
				"type": "array",
				"items": {
					"type": "string",
					"enum": ["telecom", "telecom-advanced", "5g-advanced", "satellite", "rf"]
				},
				"maxItems": 5,
				"description": "Feature groups to enable (mapped to --enable-telecom, --enable-telecom-advanced, --enable-5g-advanced, --enable-satellite, --enable-rf). Either groups or all is required"
			},
			"all": {
				"type": "boolean",
				"description": "Enable every feature group (--all); overrides/duplicates the groups selection"
			},
			"target_imsi": {
				"type": "string",
				"description": "Target IMSI for interception features (exactly 15 digits)"
			},
			"bpf_path": {
				"type": "string",
				"description": "Optional path to an existing BPF object file overriding the embedded object (-b/--bpf-path)"
			},
			"gtp_iface": {
				"type": "string",
				"description": "GTP-U interface (default: gtp0)"
			},
			"ims_iface": {
				"type": "string",
				"description": "IMS interface"
			},
			"wifi_iface": {
				"type": "string",
				"description": "WiFi interface"
			},
			"sbi_iface": {
				"type": "string",
				"description": "5G SBI (service-based interface) interface"
			},
			"sdr_iface": {
				"type": "string",
				"description": "SDR interface"
			},
			"sat_iface": {
				"type": "string",
				"description": "Satellite interface"
			},
			"wpan_iface": {
				"type": "string",
				"description": "Wireless PAN (802.15.4) interface"
			},
			"uav_iface": {
				"type": "string",
				"description": "UAV (drone) interface"
			},
			"fronthaul_iface": {
				"type": "string",
				"description": "5G fronthaul interface"
			}
		},
		"required": ["logs_dir"]
	}`)
}

func (t *OffenseStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		LogsDir        string   `json:"logs_dir"`
		Groups         []string `json:"groups"`
		All            bool     `json:"all"`
		TargetIMSI     string   `json:"target_imsi"`
		BpfPath        string   `json:"bpf_path"`
		GtpIface       string   `json:"gtp_iface"`
		ImsIface       string   `json:"ims_iface"`
		WifiIface      string   `json:"wifi_iface"`
		SbiIface       string   `json:"sbi_iface"`
		SdrIface       string   `json:"sdr_iface"`
		SatIface       string   `json:"sat_iface"`
		WpanIface      string   `json:"wpan_iface"`
		UavIface       string   `json:"uav_iface"`
		FronthaulIface string   `json:"fronthaul_iface"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	// Validate group names and dedupe, preserving request order.
	seenGroups := make(map[string]bool, len(input.Groups))
	groups := make([]string, 0, len(input.Groups))
	for _, g := range input.Groups {
		if _, ok := offenseGroupFlags[g]; !ok {
			return errorResult(fmt.Sprintf("invalid group %q: must be telecom, telecom-advanced, 5g-advanced, satellite or rf", g)), nil
		}
		if !seenGroups[g] {
			seenGroups[g] = true
			groups = append(groups, g)
		}
	}
	if !input.All && len(groups) == 0 {
		return errorResult("select at least one feature group or all"), nil
	}

	if input.TargetIMSI != "" {
		if err := validateSafeString(input.TargetIMSI, "target_imsi"); err != nil {
			return errorResult(err.Error()), nil
		}
		if !offenseIMSIRegex.MatchString(input.TargetIMSI) {
			return errorResult(fmt.Sprintf("invalid target_imsi %q: must be exactly 15 digits", input.TargetIMSI)), nil
		}
	}
	if input.BpfPath != "" {
		if err := validateInputFile(input.BpfPath, "bpf_path"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	if input.GtpIface == "" {
		input.GtpIface = "gtp0"
	}
	ifaces := []struct {
		field string
		value string
	}{
		{"gtp_iface", input.GtpIface},
		{"ims_iface", input.ImsIface},
		{"wifi_iface", input.WifiIface},
		{"sbi_iface", input.SbiIface},
		{"sdr_iface", input.SdrIface},
		{"sat_iface", input.SatIface},
		{"wpan_iface", input.WpanIface},
		{"uav_iface", input.UavIface},
		{"fronthaul_iface", input.FronthaulIface},
	}
	for _, ifc := range ifaces {
		if ifc.value == "" {
			continue
		}
		if err := validateOffenseIface(ifc.value, ifc.field); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateOutputDir(input.LogsDir, "logs_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := make([]string, 0, len(groups)+12)
	if input.All {
		args = append(args, "--all")
	} else {
		for _, g := range groups {
			args = append(args, offenseGroupFlags[g])
		}
	}
	if input.TargetIMSI != "" {
		args = append(args, "--target-imsi", input.TargetIMSI)
	}
	if input.BpfPath != "" {
		args = append(args, "--bpf-path", input.BpfPath)
	}
	// gtp_iface is always passed (with its default); the rest only when set.
	args = append(args, "--gtp-iface", input.GtpIface)
	if input.ImsIface != "" {
		args = append(args, "--ims-iface", input.ImsIface)
	}
	if input.WifiIface != "" {
		args = append(args, "--wifi-iface", input.WifiIface)
	}
	if input.SbiIface != "" {
		args = append(args, "--sbi-iface", input.SbiIface)
	}
	if input.SdrIface != "" {
		args = append(args, "--sdr-iface", input.SdrIface)
	}
	if input.SatIface != "" {
		args = append(args, "--sat-iface", input.SatIface)
	}
	if input.WpanIface != "" {
		args = append(args, "--wpan-iface", input.WpanIface)
	}
	if input.UavIface != "" {
		args = append(args, "--uav-iface", input.UavIface)
	}
	if input.FronthaulIface != "" {
		args = append(args, "--fronthaul-iface", input.FronthaulIface)
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := defenseRandomSuffix()
	stdoutPath := filepath.Join(input.LogsDir, "staticzero-offense-"+suffix+".log")
	stderrPath := filepath.Join(input.LogsDir, "staticzero-offense-"+suffix+".err")

	proc, err := t.mgr.Start(ctx, offenseBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + offenseBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## StaticZero Offense Loader Started (HIGH IMPACT)\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for stop/status chaining.
	daemonJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      offenseBinary,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", daemonJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", offenseBinary)
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", offenseBinary, strings.Join(args, " "))
	if input.All {
		sb.WriteString("- **Feature groups:** all (--all)\n")
	} else {
		fmt.Fprintf(&sb, "- **Feature groups:** %s\n", strings.Join(groups, ", "))
	}
	if input.TargetIMSI != "" {
		fmt.Fprintf(&sb, "- **Target IMSI:** %s\n", input.TargetIMSI)
	}
	fmt.Fprintf(&sb, "- **GTP interface:** %s\n", input.GtpIface)
	fmt.Fprintf(&sb, "- **Loader output (stdout):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `telecom_offense_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `telecom_offense_status` with process_id `%s` reports live state\n", proc.ID)
	sb.WriteString("- Telecom interception is regulated in many jurisdictions even in labs; authorized, isolated lab environments only.\n")
	sb.WriteString("- The daemon requires root and kernel >= 5.15; if it exits immediately, its stderr log explains why.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
