package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// maxPlanFeatures caps how many features a single plan may reference.
const maxPlanFeatures = 64

// offenseFeatureByName indexes the offense catalog by canonical name.
var offenseFeatureByName = func() map[string]offenseFeature {
	m := make(map[string]offenseFeature, len(offenseFeatures))
	for _, f := range offenseFeatures {
		m[f.Name] = f
	}
	return m
}()

// normalizeOffenseFeature accepts a feature as "enable_memfd",
// "--enable-memfd" or "enable-memfd" and returns the canonical name.
func normalizeOffenseFeature(f string) (string, error) {
	name := strings.TrimSpace(f)
	name = strings.TrimPrefix(name, "--")
	name = strings.ReplaceAll(name, "-", "_")
	if _, ok := offenseFeatureByName[name]; !ok {
		return "", fmt.Errorf("unknown offense feature %q", f)
	}
	return name, nil
}

// validOffenseFeatureList renders the accepted feature names for error
// messages.
func validOffenseFeatureList() string {
	names := make([]string, 0, len(offenseFeatures))
	for _, f := range offenseFeatures {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}

// OffensePlanTool is a dry-run planner for the Aegis-Shadow offense rootkit
// loader. It validates requested feature flags and renders the exact command
// line an operator would run manually in an authorized lab VM. It NEVER
// executes the offense binary; execution is provided separately by
// aegis_offense_start (approval-gated, authorized labs only).
type OffensePlanTool struct{}

// NewOffensePlan constructs the aegis_offense_plan tool.
func NewOffensePlan() *OffensePlanTool { return &OffensePlanTool{} }

func (t *OffensePlanTool) Name() string { return "aegis_offense_plan" }

func (t *OffensePlanTool) Description() string {
	return "Plan (dry-run) an Aegis-Shadow offense rootkit launch: validate requested --enable-* feature flags against the real offense CLI surface and render the exact command line to run manually in an authorized lab VM, with per-feature risk notes. Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. This tool is read-only and NEVER executes the offense binary."
}

func (t *OffensePlanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"features": {
				"type": "array",
				"items": {"type": "string"},
				"description": "Offense features to enable, e.g. [\"enable_memfd\", \"--enable-bpf-cloak\"] (see aegis_modules_list for the full set)"
			},
			"iface": {
				"type": "string",
				"description": "Network interface for XDP/TC attachment (default: eth0)"
			},
			"hide_pid": {
				"type": "integer",
				"description": "PID to hide on startup"
			},
			"obfuscate_inode": {
				"type": "integer",
				"description": "Inode of the file to obfuscate"
			},
			"monitor_tty": {
				"type": "string",
				"description": "TTY device to monitor, major:minor format (e.g. 136:0)"
			},
			"spoof_ppid": {
				"type": "string",
				"description": "PPID spoofing target, pid:fake_ppid format"
			},
			"timestomp": {
				"type": "string",
				"description": "Inode to timestomp, inode:atime:mtime:ctime format"
			},
			"pin_maps": {
				"type": "boolean",
				"description": "Pin BPF maps to the filesystem for persistence (adds cleanup work)"
			},
			"wipe_bytecode": {
				"type": "boolean",
				"description": "Anti-forensics: activate bytecode wipe so programs become no-ops"
			}
		},
		"required": ["features"]
	}`)
}

func (t *OffensePlanTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Features       []string `json:"features"`
		Iface          string   `json:"iface"`
		HidePID        uint32   `json:"hide_pid"`
		ObfuscateInode uint64   `json:"obfuscate_inode"`
		MonitorTTY     string   `json:"monitor_tty"`
		SpoofPPID      string   `json:"spoof_ppid"`
		Timestomp      string   `json:"timestomp"`
		PinMaps        bool     `json:"pin_maps"`
		WipeBytecode   bool     `json:"wipe_bytecode"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if len(input.Features) == 0 {
		return errorResult("features is required: pass at least one offense feature (e.g. [\"enable_memfd\"])"), nil
	}
	if len(input.Features) > maxPlanFeatures {
		return errorResult(fmt.Sprintf("too many features (max %d)", maxPlanFeatures)), nil
	}

	// Validate and dedupe features, preserving request order.
	var names []string
	seen := map[string]bool{}
	for _, f := range input.Features {
		if err := validateSafeString(f, "feature"); err != nil {
			return errorResult(err.Error()), nil
		}
		name, err := normalizeOffenseFeature(f)
		if err != nil {
			return errorResult(fmt.Sprintf("%v; valid features: %s", err, validOffenseFeatureList())), nil
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	if input.Iface != "" {
		if err := validateSafeString(input.Iface, "iface"); err != nil {
			return errorResult(err.Error()), nil
		}
		if !ifaceRegex.MatchString(input.Iface) {
			return errorResult("invalid iface: must be a plain interface name (e.g. eth0)"), nil
		}
	}
	for field, val := range map[string]string{
		"monitor_tty": input.MonitorTTY,
		"spoof_ppid":  input.SpoofPPID,
		"timestomp":   input.Timestomp,
	} {
		if val == "" {
			continue
		}
		if err := validateSafeString(val, field); err != nil {
			return errorResult(err.Error()), nil
		}
		switch field {
		case "monitor_tty", "spoof_ppid":
			if !ttyDeviceRegex.MatchString(val) {
				return errorResult(fmt.Sprintf("invalid %s: expected major:minor (u32:u32) format, got %q", field, val)), nil
			}
		case "timestomp":
			if !timestompRegex.MatchString(val) {
				return errorResult(fmt.Sprintf("invalid timestomp: expected inode:atime:mtime:ctime (u64) format, got %q", val)), nil
			}
		}
	}

	// Build the exact command line.
	args := make([]string, 0, len(names)+8)
	for _, name := range names {
		args = append(args, offenseFeatureByName[name].Flag)
	}
	if input.Iface != "" {
		args = append(args, "--iface", input.Iface)
	}
	if input.HidePID != 0 {
		args = append(args, "--hide-pid", fmt.Sprintf("%d", input.HidePID))
	}
	if input.ObfuscateInode != 0 {
		args = append(args, "--obfuscate-inode", fmt.Sprintf("%d", input.ObfuscateInode))
	}
	if input.MonitorTTY != "" {
		args = append(args, "--monitor-tty", input.MonitorTTY)
	}
	if input.SpoofPPID != "" {
		args = append(args, "--spoof-ppid", input.SpoofPPID)
	}
	if input.Timestomp != "" {
		args = append(args, "--timestomp", input.Timestomp)
	}
	if input.PinMaps {
		args = append(args, "--pin-maps")
	}
	if input.WipeBytecode {
		args = append(args, "--wipe-bytecode")
	}
	commandLine := "sudo ./offense " + strings.Join(args, " ")

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Offense Plan (DRY RUN — nothing was executed)\n\n")
	sb.WriteString("Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only.\n\n")
	sb.WriteString("**This tool never executes the offense binary.** It only validates the requested feature flags and renders the exact command line for you to run manually inside your authorized, isolated lab VM.\n\n")

	sb.WriteString("### Planned command (run manually in your lab VM)\n\n")
	sb.WriteString("```\n")
	sb.WriteString(commandLine + "\n")
	sb.WriteString("```\n\n")
	sb.WriteString("The binary is built as `offense` by cargo (e.g. `target/release/offense`); adjust the path to your build. Requires root. It is a daemon: runs until Ctrl+C or C2 kill switch.\n\n")

	sb.WriteString("### Requested features\n\n")
	sb.WriteString("| Flag | Feature | Hook point | Risk notes |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, name := range names {
		f := offenseFeatureByName[name]
		fmt.Fprintf(&sb, "| `%s` | %s (%s) | %s | %s |\n", f.Flag, f.Description, f.ID, f.HookPoint, f.Risk)
	}

	if input.PinMaps || input.WipeBytecode || input.ObfuscateInode != 0 || input.Timestomp != "" || input.SpoofPPID != "" || input.HidePID != 0 || input.MonitorTTY != "" {
		sb.WriteString("\n### High-impact options requested\n\n")
		if input.PinMaps {
			sb.WriteString("- `--pin-maps`: maps are pinned under `/sys/fs/bpf` — remove them manually after the exercise (`rm` under the pin path) or they persist.\n")
		}
		if input.WipeBytecode {
			sb.WriteString("- `--wipe-bytecode`: anti-forensics — loaded programs become no-ops while remaining attached. Expect detection tools to see coverage without events.\n")
		}
		if input.HidePID != 0 {
			fmt.Fprintf(&sb, "- `--hide-pid %d`: the PID is hidden from getdents64-based listings immediately on startup.\n", input.HidePID)
		}
		if input.ObfuscateInode != 0 {
			fmt.Fprintf(&sb, "- `--obfuscate-inode %d`: reads of the matching inode are obfuscated at the vfs_read path.\n", input.ObfuscateInode)
		}
		if input.MonitorTTY != "" {
			fmt.Fprintf(&sb, "- `--monitor-tty %s`: keystrokes on this TTY are harvested (credential capture).\n", input.MonitorTTY)
		}
		if input.SpoofPPID != "" {
			fmt.Fprintf(&sb, "- `--spoof-ppid %s`: /proc ancestry is falsified for the target PID.\n", input.SpoofPPID)
		}
		if input.Timestomp != "" {
			fmt.Fprintf(&sb, "- `--timestomp %s`: file timestamps are falsified at the vfs_getattr path.\n", input.Timestomp)
		}
	}

	sb.WriteString("\n### Always-loaded base features (not flag-gated)\n\n")
	sb.WriteString("Regardless of the flags above, the offense daemon unconditionally loads:\n\n")
	for _, f := range offenseBaseFeatures {
		fmt.Fprintf(&sb, "- %s\n", f)
	}

	sb.WriteString("\n### Operator checklist\n\n")
	sb.WriteString("1. Run only inside an isolated, snapshotted lab VM with explicit written authorization.\n")
	sb.WriteString("2. Keep the defense daemon (`defense --all-modules -o alerts.ndjson`) running to capture detections for comparison.\n")
	sb.WriteString("3. The rootkit detaches its programs on Ctrl+C; verify cleanup afterwards with `sudo bpftool prog show` and `ls /sys/fs/bpf`.\n")
	sb.WriteString("4. Never expose the lab VM's interfaces (`--iface`) to production networks.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
