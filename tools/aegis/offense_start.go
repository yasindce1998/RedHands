package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// offenseBinary is the allowlist name of the Aegis-Shadow offense rootkit
// loader daemon.
const offenseBinary = "aegis-shadow-offense"

// validOffenseFeatureNames is the exact --enable-* flag surface of the
// aegis-shadow-offense release binary (v0.1.1), transcribed as flag names
// without the --enable- prefix. deadman-switch is the scorched-earth
// feature; it is opt-in via the features list or the deadman_switch param.
var validOffenseFeatureNames = []string{
	"netns-hide", "bpf-cloak", "module-mask", "memfd", "syslog-strip",
	"icmp-exfil", "socket-clone", "cred-relay", "container-probe",
	"kprobe-evasion", "tail-calls", "ftrace-blind", "bpf-iter-abuse",
	"vdso-hook", "shm-covert", "uffd-inject", "coredump-suppress",
	"isn-covert", "ipv6-ext", "arp-poison", "port-knock", "bgp-hijack",
	"dr-abuse", "pmc-covert", "tsc-sidechan", "audit-kill", "inode-slack",
	"journal-manip", "proc-spoof", "initramfs", "modsign-bypass",
	"polymorphic", "phantom-stack", "container-lateral", "dma-covert",
	"behavioral-ai", "supply-chain", "bpf-parasitism", "kernel-object",
	"network-stealth", "persistence2", "deadman-switch",
}

// validOffenseFeatureSet indexes validOffenseFeatureNames for lookup.
var validOffenseFeatureSet = func() map[string]bool {
	m := make(map[string]bool, len(validOffenseFeatureNames))
	for _, f := range validOffenseFeatureNames {
		m[f] = true
	}
	return m
}()

// offenseFeatureList renders the valid feature names for error messages.
var offenseFeatureList = strings.Join(validOffenseFeatureNames, ", ")

// OffenseStartTool starts the Aegis-Shadow offense rootkit loader
// (aegis-shadow-offense) as a managed background process via the
// BackgroundManager, which enforces the same binary allowlist and argument
// validation as the regular executor.
type OffenseStartTool struct {
	mgr *executor.BackgroundManager
}

// NewOffenseStart constructs the aegis_offense_start tool.
func NewOffenseStart(mgr *executor.BackgroundManager) *OffenseStartTool {
	return &OffenseStartTool{mgr: mgr}
}

func (t *OffenseStartTool) Name() string { return "aegis_offense_start" }

func (t *OffenseStartTool) Description() string {
	return "Launch the Aegis-Shadow eBPF rootkit loader (aegis-shadow-offense) as a managed background process in an authorized lab VM: selected --enable-* features (e.g. memfd, kprobe-evasion), interface for XDP/TC attachment, and optional hide/obfuscate/monitor/spoof/timestomp targets. Human-readable logs stream to <logs_dir>/aegis-offense-<id>.log; logs go to <logs_dir>/aegis-offense-<id>.err. Destructive capabilities — the dead-man switch (deadman_switch param or the deadman-switch feature, scorched-earth wipe on tamper/timeout) and bytecode wipe (wipe_bytecode param, wipes eBPF bytecode from memory after load) — are opt-in with explicit warnings and can render the lab VM unrecoverable. Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Requires root/eBPF privileges; high-impact: runs a privileged rootkit daemon until aegis_offense_stop is called. Approval-gated. If the daemon exits immediately (missing privileges), check the stderr log via aegis_offense_status."
}

func (t *OffenseStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"logs_dir": {
				"type": "string",
				"description": "Required directory for daemon output files; created with 0700 if missing. Loader output (stdout) and logs (stderr) are written here"
			},
			"iface": {
				"type": "string",
				"description": "Network interface for XDP/TC attachment (default: eth0)"
			},
			"features": {
				"type": "array",
				"items": {"type": "string"},
				"maxItems": 43,
				"description": "Feature flag names without the --enable- prefix (e.g. [\"memfd\",\"kprobe-evasion\"]). Valid names: netns-hide, bpf-cloak, module-mask, memfd, syslog-strip, icmp-exfil, socket-clone, cred-relay, container-probe, kprobe-evasion, tail-calls, ftrace-blind, bpf-iter-abuse, vdso-hook, shm-covert, uffd-inject, coredump-suppress, isn-covert, ipv6-ext, arp-poison, port-knock, bgp-hijack, dr-abuse, pmc-covert, tsc-sidechan, audit-kill, inode-slack, journal-manip, proc-spoof, initramfs, modsign-bypass, polymorphic, phantom-stack, container-lateral, dma-covert, behavioral-ai, supply-chain, bpf-parasitism, kernel-object, network-stealth, persistence2, deadman-switch. Note: deadman-switch is destructive (scorched-earth wipe); prefer the deadman_switch param for explicitness"
			},
			"hide_pid": {
				"type": "integer",
				"minimum": 1,
				"description": "PID to hide on startup"
			},
			"obfuscate_inode": {
				"type": "integer",
				"minimum": 1,
				"description": "Inode of the file to obfuscate"
			},
			"monitor_tty": {
				"type": "string",
				"description": "TTY device to monitor for credentials, major:minor format (e.g. 136:0)"
			},
			"spoof_ppid": {
				"type": "string",
				"description": "PPID spoofing target, pid:fake_ppid format (e.g. 1234:1)"
			},
			"timestomp": {
				"type": "string",
				"description": "Fake timestamps for an inode, inode:atime:mtime:ctime format"
			},
			"pin_maps": {
				"type": "boolean",
				"description": "Pin BPF maps to the filesystem for persistence (adds cleanup work under /sys/fs/bpf)"
			},
			"verbose": {
				"type": "boolean",
				"description": "Verbose logging (-v)"
			},
			"deadman_switch": {
				"type": "boolean",
				"description": "DESTRUCTIVE (opt-in, default false): pass --enable-deadman-switch. Scorched-earth wipe triggers on tamper/timeout; the lab VM may become unrecoverable. Use only on disposable, snapshotted lab VMs"
			},
			"wipe_bytecode": {
				"type": "boolean",
				"description": "DESTRUCTIVE (opt-in, default false): pass --wipe-bytecode. eBPF bytecode is wiped from memory after load, defeating live forensics"
			}
		},
		"required": ["logs_dir"]
	}`)
}

func (t *OffenseStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		LogsDir         string   `json:"logs_dir"`
		Iface           string   `json:"iface"`
		Features        []string `json:"features"`
		HidePID         *int     `json:"hide_pid"`
		ObfuscateInode  *int     `json:"obfuscate_inode"`
		MonitorTTY      string   `json:"monitor_tty"`
		SpoofPPID       string   `json:"spoof_ppid"`
		Timestomp       string   `json:"timestomp"`
		PinMaps         bool     `json:"pin_maps"`
		Verbose         bool     `json:"verbose"`
		DeadmanSwitch   bool     `json:"deadman_switch"`
		WipeBytecode    bool     `json:"wipe_bytecode"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	// Validate feature names against the verified release flag surface.
	if len(input.Features) > len(validOffenseFeatureNames) {
		return errorResult(fmt.Sprintf("features accepts at most %d entries", len(validOffenseFeatureNames))), nil
	}
	features := make([]string, 0, len(input.Features)+1)
	seenFeatures := make(map[string]bool, len(input.Features)+1)
	for _, f := range input.Features {
		if err := validateSafeString(f, "features entry"); err != nil {
			return errorResult(err.Error()), nil
		}
		if !validOffenseFeatureSet[f] {
			return errorResult(fmt.Sprintf("unknown offense feature %q; valid features: %s", f, offenseFeatureList)), nil
		}
		if !seenFeatures[f] {
			seenFeatures[f] = true
			features = append(features, f)
		}
	}
	// The deadman_switch bool is equivalent to listing deadman-switch in
	// features; merge so the flag is passed exactly once.
	deadmanActive := input.DeadmanSwitch
	if input.DeadmanSwitch && !seenFeatures["deadman-switch"] {
		seenFeatures["deadman-switch"] = true
		features = append(features, "deadman-switch")
	}
	if seenFeatures["deadman-switch"] {
		deadmanActive = true
	}

	if input.Iface == "" {
		input.Iface = "eth0"
	}
	if err := validateSafeString(input.Iface, "iface"); err != nil {
		return errorResult(err.Error()), nil
	}
	if !ifaceRegex.MatchString(input.Iface) {
		return errorResult("invalid iface: must be a plain interface name (e.g. eth0)"), nil
	}
	if input.HidePID != nil && *input.HidePID < 1 {
		return errorResult("hide_pid must be a positive integer"), nil
	}
	if input.ObfuscateInode != nil && *input.ObfuscateInode < 1 {
		return errorResult("obfuscate_inode must be a positive integer"), nil
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
	if err := validateOutputDir(input.LogsDir, "logs_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	// Build the command line. --enable-deadman-switch only arrives via the
	// merged feature list; --wipe-bytecode only via its explicit bool.
	args := make([]string, 0, len(features)+9)
	for _, f := range features {
		args = append(args, "--enable-"+f)
	}
	args = append(args, "--iface", input.Iface)
	if input.HidePID != nil {
		args = append(args, "--hide-pid", strconv.Itoa(*input.HidePID))
	}
	if input.ObfuscateInode != nil {
		args = append(args, "--obfuscate-inode", strconv.Itoa(*input.ObfuscateInode))
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
	if input.Verbose {
		args = append(args, "--verbose")
	}
	if input.WipeBytecode {
		args = append(args, "--wipe-bytecode")
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := defenseRandomSuffix()
	stdoutPath := filepath.Join(input.LogsDir, "aegis-offense-"+suffix+".log")
	stderrPath := filepath.Join(input.LogsDir, "aegis-offense-"+suffix+".err")

	proc, err := t.mgr.Start(ctx, offenseBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + offenseBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Offense Rootkit Loader Started (HIGH IMPACT)\n\n")
	if deadmanActive || input.WipeBytecode {
		sb.WriteString("⚠️  DESTRUCTIVE FEATURES ACTIVE ⚠️\n\n")
		if deadmanActive {
			sb.WriteString("- deadman-switch: scorched-earth wipe triggers on tamper/timeout — the lab VM may become unrecoverable\n")
		}
		if input.WipeBytecode {
			sb.WriteString("- wipe-bytecode: eBPF bytecode is wiped from memory after load, defeating live forensics\n")
		}
		sb.WriteString("Use only on disposable, snapshotted lab VMs. Data loss is expected behavior.\n\n")
	}
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
	if len(features) == 0 {
		sb.WriteString("- **Features:** none (base rootkit features only)\n")
	} else {
		fmt.Fprintf(&sb, "- **Features:** %s\n", strings.Join(features, ", "))
	}
	fmt.Fprintf(&sb, "- **Interface:** %s\n", input.Iface)
	fmt.Fprintf(&sb, "- **Loader output (stdout):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `aegis_offense_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `aegis_offense_status` with process_id `%s` reports live state\n", proc.ID)
	sb.WriteString("- The daemon requires root/eBPF and runs until stopped; if it exits immediately, its stderr log explains why.\n")
	sb.WriteString("- Authorized, isolated lab VM only — educational/VM-only posture; never expose --iface to production networks.\n")
	sb.WriteString("- Verify cleanup afterwards with `sudo bpftool prog show` and `ls /sys/fs/bpf` (especially with pin_maps).\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
