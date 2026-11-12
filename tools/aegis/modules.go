package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// defenseModule describes one per-module detection flag of the Aegis-Shadow
// defense daemon. Entries are transcribed from defense/src/main.rs (flag
// list, attach points) and defense/src/lib.rs (classified alert types).
type defenseModule struct {
	Number      int
	Name        string
	Flag        string
	HookPoint   string
	AlertType   string
	Description string
}

// defenseModules is the catalog of the 15 per-module detection flags.
var defenseModules = []defenseModule{
	{Number: 1, Name: "Ghost Map Detection", Flag: "--ghost-maps", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "Ghost Map Detected", Description: "Detects BPF maps created outside the visible map inventory (maps used to hide rootkit state)."},
	{Number: 2, Name: "Syscall Latency Monitoring", Flag: "--syscall-latency", HookPoint: "tracepoints raw_syscalls/sys_enter + sys_exit", AlertType: "Syscall Latency Anomaly", Description: "Baselines syscall timing during the calibration period, then alerts on latency anomalies caused by hooks."},
	{Number: 3, Name: "Bytecode Integrity Checking", Flag: "--bytecode-check", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "Bytecode Tampering", Description: "Checksums loaded program bytecode and alerts when a program is mutated after verification."},
	{Number: 4, Name: "Hidden Process Detection", Flag: "--hidden-process", HookPoint: "kprobe __x64_sys_getdents64", AlertType: "Hidden Process Detected", Description: "Compares getdents64 results against the task list to reveal PIDs hidden by rootkits."},
	{Number: 5, Name: "Suspicious Hook Detection", Flag: "--suspicious-hooks", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "Suspicious Hook Detected", Description: "Flags suspicious hook targets and attach points observed via bpf() syscalls."},
	{Number: 6, Name: "eBPF Program Inventory", Flag: "--prog-inventory", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "Program Inventory Gap", Description: "Tracks program IDs and alerts on gaps that indicate programs hidden from userspace."},
	{Number: 7, Name: "Syscall Argument Anomaly Profiling", Flag: "--syscall-anomaly", HookPoint: "tracepoint raw_syscalls/sys_enter", AlertType: "Syscall Argument Anomaly", Description: "Profiles syscall argument distributions per PID and alerts on deviations."},
	{Number: 8, Name: "Network Behavior Baseline", Flag: "--net-baseline", HookPoint: "kprobe tcp_connect", AlertType: "Network Behavior Anomaly", Description: "Baselines outbound connection behavior and alerts on anomalous volumes or destinations."},
	{Number: 9, Name: "Memory-Backed Execution Detection", Flag: "--memfd-detect", HookPoint: "kprobes __x64_sys_memfd_create + do_execveat_common", AlertType: "Memory-Backed Execution", Description: "Detects fileless execution staged via memfd_create and execveat."},
	{Number: 10, Name: "BPF Map Content Auditing", Flag: "--map-audit", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "BPF Map C2 Signature", Description: "Audits map contents for command-and-control signatures."},
	{Number: 11, Name: "Tracepoint Coverage Monitoring", Flag: "--tracepoint-monitor", HookPoint: "kprobe bpf_prog_put", AlertType: "Rapid BPF Detach", Description: "Detects rapid program detachment that blinds monitoring tracepoints."},
	{Number: 12, Name: "Cross-Reference Detection", Flag: "--cross-reference", HookPoint: "tracepoint sched/sched_process_fork", AlertType: "Cross-Reference Anomaly", Description: "Cross-references kernel data sources and alerts on discrepancies (anti-cloaking)."},
	{Number: 13, Name: "Hardware Performance Counter Monitoring", Flag: "--hw-perf-counters", HookPoint: "kprobe perf_event_open", AlertType: "HW Perf Counter Deviation", Description: "Watches hardware counters for deviations caused by hidden work or hooking."},
	{Number: 14, Name: "eBPF Verifier Log Analysis", Flag: "--verifier-analysis", HookPoint: "tracepoint syscalls/sys_enter_bpf", AlertType: "Suspicious BPF Program", Description: "Analyzes verifier logs for suspicious program patterns."},
	{Number: 15, Name: "Kernel Data Structure Memory Forensics", Flag: "--memory-forensics", HookPoint: "kprobe schedule", AlertType: "Kernel Data Tampering", Description: "Checksums kernel data structures to detect direct kernel memory tampering."},
}

// defenseHoneypots is the decoy-map capability, exposed as its own flag.
var defenseHoneypots = defenseModule{
	Number:      0,
	Name:        "Honeypot BPF Maps",
	Flag:        "--honeypots",
	HookPoint:   "userspace decoys pinned at /sys/fs/bpf/honeypot",
	AlertType:   "Honeypot Map Accessed",
	Description: "Deploys decoy maps (shadow_config, rootkit_pids, c2_keys) and alerts when a rootkit reads them.",
}

// defenseDaemonFlags documents the defense daemon's non-module CLI surface.
var defenseDaemonFlags = []struct {
	Flag    string
	Meaning string
}{
	{Flag: "-o, --output <file>", Meaning: "Append alert records as NDJSON to a file"},
	{Flag: "-t, --threshold <1-4>", Meaning: "Minimum alert severity to emit (1=Low, 2=Medium, 3=High, 4=Critical; default 2)"},
	{Flag: "--all-modules", Meaning: "Enable all 15 detection modules"},
	{Flag: "--auto-detach", Meaning: "Response: flag malicious BPF programs for detachment after corroborating alerts"},
	{Flag: "--auto-contain", Meaning: "Response: isolate attack-chain PIDs via cgroups (memory.max 64MB, cpu.weight 1)"},
	{Flag: "--calibration-period <secs>", Meaning: "Baseline calibration period before anomaly detection activates (default 60)"},
	{Flag: "--config <json>", Meaning: "Runtime config file ({\"threshold\":N,\"window_secs\":N}), hot-reloaded every 5s"},
	{Flag: "--enable-ml", Meaning: "Adversarial ML detection layer"},
	{Flag: "--json-stdout", Meaning: "Stream alerts as NDJSON on stdout, logs to stderr (consumed by the Go TUI bridge)"},
	{Flag: "-v, --verbose", Meaning: "Verbose logging"},
}

// offenseFeature describes one --enable-* feature flag of the Aegis-Shadow
// offense rootkit loader. Entries are transcribed from offense/src/main.rs.
type offenseFeature struct {
	Name        string // canonical underscore name, e.g. "enable_netns_hide"
	Flag        string // CLI flag, e.g. "--enable-netns-hide"
	ID          string // feature group label used in the source
	Description string
	HookPoint   string
	Risk        string
}

// offenseFeatures is the full flag-gated offense catalog (F14+). Features
// F1-F13 plus the bytecode-wipe check are always loaded and have no flag.
var offenseFeatures = []offenseFeature{
	{Name: "enable_netns_hide", Flag: "--enable-netns-hide", ID: "F14", Description: "Network namespace hiding", HookPoint: "kprobe __x64_sys_setns", Risk: "Hides namespaces from setns-based inspection; breaks nsenter forensics."},
	{Name: "enable_bpf_cloak", Flag: "--enable-bpf-cloak", ID: "F15", Description: "eBPF program cloaking (hides own prog IDs)", HookPoint: "kprobes __x64_sys_bpf", Risk: "Defeats program-inventory detectors (defense module 6); own programs become invisible."},
	{Name: "enable_module_mask", Flag: "--enable-module-mask", ID: "F16", Description: "Kernel module masquerading (/proc/modules)", HookPoint: "kprobe vfs_read", Risk: "Fakes module listings; undermines lsmod-based inventory."},
	{Name: "enable_memfd", Flag: "--enable-memfd", ID: "F17", Description: "Memory-only payload staging (memfd_create + execveat)", HookPoint: "kprobes __x64_sys_memfd_create + do_execveat_common", Risk: "Fileless execution; no on-disk artifacts for forensics."},
	{Name: "enable_syslog_strip", Flag: "--enable-syslog-strip", ID: "F18", Description: "Syslog write stripping", HookPoint: "kprobe ksys_write", Risk: "Corrupts syslog evidence at the write path."},
	{Name: "enable_icmp_exfil", Flag: "--enable-icmp-exfil", ID: "F20", Description: "ICMP covert channel exfiltration", HookPoint: "TC egress on --iface", Risk: "Data leaves inside ICMP payloads; watch for anomalous ICMP bursts."},
	{Name: "enable_socket_clone", Flag: "--enable-socket-clone", ID: "F21", Description: "Socket cloning / connection shadowing", HookPoint: "kprobe tcp_sendmsg", Risk: "Intercepts and may duplicate live session traffic."},
	{Name: "enable_cred_relay", Flag: "--enable-cred-relay", ID: "F22", Description: "Credential relay over C2", HookPoint: "CRED_EVENTS ring buffer + DNS/ICMP exfil queues", Risk: "Harvested credentials leave the VM via the C2 channel."},
	{Name: "enable_container_probe", Flag: "--enable-container-probe", ID: "F23", Description: "Container escape probes", HookPoint: "kprobes __x64_sys_unshare + commit_creds", Risk: "Actively probes escape paths; can destabilize the kernel."},
	{Name: "enable_kprobe_evasion", Flag: "--enable-kprobe-evasion", ID: "F25", Description: "Kprobe detection & evasion", HookPoint: "kprobe register_kprobe", Risk: "Creates blind spots in kprobe-based monitoring."},
	{Name: "enable_tail_calls", Flag: "--enable-tail-calls", ID: "F26", Description: "eBPF tail-call chains", HookPoint: "kprobe __x64_sys_getpid + TAIL_CALL_PROGS program array", Risk: "Chained programs complicate static analysis and attribution."},
	{Name: "enable_ftrace_blind", Flag: "--enable-ftrace-blind", ID: "F27", Description: "Ftrace/perf event blinding", HookPoint: "kprobe perf_event_open", Risk: "Hides activity from ftrace/perf tracers."},
	{Name: "enable_bpf_iter_abuse", Flag: "--enable-bpf-iter-abuse", ID: "F28", Description: "BPF iterator abuse", HookPoint: "kprobe bpf_iter_run_prog", Risk: "Privileged reads via iterators; hard to attribute."},
	{Name: "enable_vdso_hook", Flag: "--enable-vdso-hook", ID: "F29", Description: "VDSO/vsyscall hooking", HookPoint: "kprobe arch_setup_additional_pages", Risk: "Silently intercepts userland timing/syscall paths."},
	{Name: "enable_shm_covert", Flag: "--enable-shm-covert", ID: "F30", Description: "Shared memory covert channel", HookPoint: "kprobe do_shmat", Risk: "Cross-process covert channel with no network artifacts."},
	{Name: "enable_uffd_inject", Flag: "--enable-uffd-inject", ID: "F31", Description: "userfaultfd process injection", HookPoint: "kprobe userfaultfd_ioctl", Risk: "User-space controlled page faults; memory corruption risk."},
	{Name: "enable_coredump_suppress", Flag: "--enable-coredump-suppress", ID: "F32", Description: "Core dump suppression", HookPoint: "kprobe do_coredump", Risk: "Destroys crash-dump forensic evidence."},
	{Name: "enable_isn_covert", Flag: "--enable-isn-covert", ID: "F33", Description: "TCP ISN covert channel", HookPoint: "TC egress on --iface", Risk: "Encodes data in initial sequence numbers; stealthy egress."},
	{Name: "enable_ipv6_ext", Flag: "--enable-ipv6-ext", ID: "F34", Description: "IPv6 extension header abuse", HookPoint: "TC egress on --iface", Risk: "Hides data where many IDS engines do not inspect."},
	{Name: "enable_arp_poison", Flag: "--enable-arp-poison", ID: "F35", Description: "ARP cache poisoning", HookPoint: "XDP on --iface", Risk: "MITMs the lab segment; disruptive beyond the host."},
	{Name: "enable_port_knock", Flag: "--enable-port-knock", ID: "F36", Description: "XDP port knocking daemon", HookPoint: "XDP on --iface", Risk: "Hidden service access path (backdoor)."},
	{Name: "enable_bgp_hijack", Flag: "--enable-bgp-hijack", ID: "F37", Description: "BGP hijacking", HookPoint: "TC egress on --iface", Risk: "Route hijack logic; lab-network disruption."},
	{Name: "enable_dr_abuse", Flag: "--enable-dr-abuse", ID: "F38", Description: "Hardware breakpoint (DR register) abuse", HookPoint: "kprobe arch_install_hw_breakpoint", Risk: "Stealthy traps via debug registers."},
	{Name: "enable_pmc_covert", Flag: "--enable-pmc-covert", ID: "F39", Description: "CPU performance counter covert channel", HookPoint: "kprobe perf_event_read", Risk: "Side-channel exfil invisible to network tools."},
	{Name: "enable_tsc_sidechan", Flag: "--enable-tsc-sidechan", ID: "F40", Description: "TSC timing side channel", HookPoint: "kprobes crypto_skcipher_encrypt", Risk: "Key-timing leakage on crypto paths."},
	{Name: "enable_audit_kill", Flag: "--enable-audit-kill", ID: "F41", Description: "Audit subsystem kill", HookPoint: "kprobe audit_receive_msg", Risk: "Blinds audit subsystem messaging (auditd)."},
	{Name: "enable_inode_slack", Flag: "--enable-inode-slack", ID: "F42", Description: "Inode slack-space hiding", HookPoint: "kprobe vfs_write", Risk: "Anti-forensics: data hidden in slack space."},
	{Name: "enable_journal_manip", Flag: "--enable-journal-manip", ID: "F43", Description: "ext4 journal manipulation", HookPoint: "kprobe jbd2_journal_commit_transaction", Risk: "Persistent, low-level filesystem log corruption."},
	{Name: "enable_proc_spoof", Flag: "--enable-proc-spoof", ID: "F44", Description: "/proc deep spoofing", HookPoint: "kprobe seq_read", Risk: "Fake process trees and stats for investigators."},
	{Name: "enable_initramfs", Flag: "--enable-initramfs", ID: "F45", Description: "Initramfs implant", HookPoint: "kprobe init_module", Risk: "Early-boot persistence before detection tools start."},
	{Name: "enable_modsign_bypass", Flag: "--enable-modsign-bypass", ID: "F46", Description: "Kernel module signing bypass", HookPoint: "kprobe module_sig_check", Risk: "Loads unsigned modules; defeats the secure boot chain."},
	{Name: "enable_bpf_obf_pin", Flag: "--enable-bpf-obf-pin", ID: "F47", Description: "BPF link pinning with obfuscated paths", HookPoint: "kprobe bpf_obj_get", Risk: "Persistence via pinned objects at hidden paths."},
	{Name: "enable_hypervisor_evasion", Flag: "--enable-hypervisor-evasion", ID: "F48-F51", Description: "Hypervisor-aware evasion", HookPoint: "kprobes kvm_emulate_cpuid + kvm_hypercall + exc_nmi + tsc_khz_changed", Risk: "Evades hypervisor introspection; hides VM presence."},
	{Name: "enable_polymorphic", Flag: "--enable-polymorphic", ID: "F52-F54", Description: "Polymorphic/self-rewriting bytecode", HookPoint: "kprobes bpf_prog_load + __schedule + bpf_check", Risk: "Signature evasion; bytecode changes shape over time."},
	{Name: "enable_phantom_stack", Flag: "--enable-phantom-stack", ID: "F55-F57", Description: "Phantom TCP stack in XDP/TC", HookPoint: "XDP + kprobe tcp_rcv_state_process + TC egress", Risk: "Hidden TCP sessions invisible to host stack tools."},
	{Name: "enable_container_lateral", Flag: "--enable-container-lateral", ID: "F58-F60", Description: "Cross-container lateral movement", HookPoint: "kprobes cgroup_bpf_prog_attach + switch_task_namespaces + commit_creds", Risk: "Escapes container isolation boundaries."},
	{Name: "enable_dma_covert", Flag: "--enable-dma-covert", ID: "F61-F63", Description: "DMA/PCIe covert channels", HookPoint: "kprobes iommu_map + pci_read_config_dword + ndo_start_xmit", Risk: "Bypasses CPU-based controls; NIC/DMA level exfil."},
	{Name: "enable_behavioral_ai", Flag: "--enable-behavioral-ai", ID: "F64-F66", Description: "AI-driven behavioral camouflage", HookPoint: "tracepoint raw_syscalls/sys_enter + kprobes __schedule", Risk: "Mimics benign behavior to defeat anomaly detection."},
	{Name: "enable_supply_chain", Flag: "--enable-supply-chain", ID: "F67-F69", Description: "Supply chain persistence hooks", HookPoint: "kprobes do_execveat_common + vfs_read + security_file_open", Risk: "Hooks exec/open integrity paths; persistence in build pipelines."},
	{Name: "enable_deadman_switch", Flag: "--enable-deadman-switch", ID: "F70-F72", Description: "Dead man's switch heartbeat monitor", HookPoint: "kprobes udp_rcv + hrtimer_interrupt + vfs_unlink", Risk: "Scorched-earth deletion on heartbeat loss; destructive."},
	{Name: "enable_bpf_parasitism", Flag: "--enable-bpf-parasitism", ID: "F73-F75", Description: "BPF-to-BPF parasitism", HookPoint: "tracepoint syscalls/sys_enter_bpf + kprobes bpf_prog_array_copy + bpf_map_update_elem", Risk: "Piggybacks on legitimate programs; attribution nightmare."},
	{Name: "enable_kernel_object", Flag: "--enable-kernel-object", ID: "F76-F80", Description: "Advanced kernel object manipulation", HookPoint: "kprobes __switch_to + security_file_open + native_load_idt + bpf_prog_get_info_by_id + klp_enable_patch", Risk: "Task struct/IDT/LSM/livepatch manipulation; kernel integrity loss."},
	{Name: "enable_network_stealth", Flag: "--enable-network-stealth", ID: "F81-F84", Description: "Network stealth layer", HookPoint: "XDP + TC egress + kprobe tcp_sendmsg (note: hardcodes eth0 in v0.1)", Risk: "Raw XDP/TC C2 plus traffic shaping; covert egress."},
	{Name: "enable_persistence2", Flag: "--enable-persistence2", ID: "F85-F88", Description: "Advanced persistence mechanisms", HookPoint: "kprobes bpf_obj_pin + cgroup_bpf_prog_attach + module_param_sysfs_setup + do_init_module", Risk: "Survives cleanup via pinned objects, cgroup and module hooks."},
}

// offenseBaseFeatures are loaded unconditionally by the offense binary and
// cannot be disabled via CLI flags.
var offenseBaseFeatures = []string{
	"F1 Process hiding (kprobes on __x64_sys_getdents64)",
	"F2 Network stealth (XDP attached to --iface)",
	"F3 File obfuscation (kprobe vfs_read)",
	"F4 Telemetry muting (kprobes audit_log_start/audit_log_end)",
	"F6 Credential harvesting (kprobe ksys_write)",
	"F7 Log tampering (kprobes do_syslog)",
	"F8 Process ancestry spoofing (kprobe vfs_read on /proc/<pid>/status)",
	"F9 DNS exfiltration (TC egress on --iface)",
	"F10 Kallsyms hiding (kprobe vfs_read)",
	"F11 Anti-detach self-defense (tracepoint syscalls/sys_enter_bpf)",
	"F13 Timestomping (kprobes vfs_getattr)",
	"F19 Bytecode wipe check (kprobe __x64_sys_getpid; activated by --wipe-bytecode)",
}

// offenseOptionFlags documents the offense daemon's non-enable CLI options.
var offenseOptionFlags = []struct {
	Flag    string
	Format  string
	Meaning string
}{
	{Flag: "--iface <name>", Format: "interface name (default: eth0)", Meaning: "Network interface for XDP/TC attachment"},
	{Flag: "--hide-pid <pid>", Format: "u32", Meaning: "Hide a specific PID on startup"},
	{Flag: "--obfuscate-inode <inode>", Format: "u64", Meaning: "Obfuscate a file by inode"},
	{Flag: "--monitor-tty <major:minor>", Format: "e.g. 136:0", Meaning: "Monitor a TTY device for credentials"},
	{Flag: "--spoof-ppid <pid:fake_ppid>", Format: "u32:u32", Meaning: "Spoof the PPID of a target PID"},
	{Flag: "--timestomp <inode:atime:mtime:ctime>", Format: "u64:u64:u64:u64", Meaning: "Fake timestamps for an inode"},
	{Flag: "--pin-maps", Format: "boolean", Meaning: "Pin BPF maps to the filesystem for persistence"},
	{Flag: "--wipe-bytecode", Format: "boolean", Meaning: "Anti-forensics: programs become no-ops"},
}

// ModulesListTool renders the static Aegis-Shadow module catalog. No binary
// is executed.
type ModulesListTool struct{}

// NewModulesList constructs the aegis_modules_list tool.
func NewModulesList() *ModulesListTool { return &ModulesListTool{} }

func (t *ModulesListTool) Name() string { return "aegis_modules_list" }

func (t *ModulesListTool) Description() string {
	return "List the Aegis-Shadow reference catalog: the 15 defense detection modules (name, CLI flag, eBPF hook point, alert type) and the offense rootkit feature groups with risk notes. Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Static reference data transcribed from the Aegis-Shadow sources; no binary is executed."
}

func (t *ModulesListTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"component": {
				"type": "string",
				"enum": ["defense", "offense"],
				"description": "Restrict the catalog to one component (default: both)"
			}
		},
		"required": []
	}`)
}

func (t *ModulesListTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Component string `json:"component"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	switch input.Component {
	case "", "defense", "offense":
	default:
		return errorResult("invalid component: must be defense or offense"), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Module Catalog\n\n")
	sb.WriteString("Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Reference data only; no binaries are executed by this tool.\n\n")

	if input.Component == "" || input.Component == "defense" {
		sb.WriteString("### Defense daemon (binary `defense`, clap name `aegis-shadow-defense`)\n\n")
		sb.WriteString("Long-running daemon: runs until Ctrl+C (SIGINT), exits 0. With no module flags it warns and exits immediately.\n\n")
		sb.WriteString("#### Detection modules\n\n")
		sb.WriteString("| # | Module | Flag | Hook point | Alert type |\n")
		sb.WriteString("|---|---|---|---|---|\n")
		for _, m := range defenseModules {
			fmt.Fprintf(&sb, "| %d | %s | `%s` | %s | %s |\n", m.Number, m.Name, m.Flag, m.HookPoint, m.AlertType)
		}
		fmt.Fprintf(&sb, "| - | %s | `%s` | %s | %s |\n", defenseHoneypots.Name, defenseHoneypots.Flag, defenseHoneypots.HookPoint, defenseHoneypots.AlertType)
		sb.WriteString("\nModule descriptions:\n\n")
		for _, m := range defenseModules {
			fmt.Fprintf(&sb, "- `%s` %s: %s\n", m.Flag, m.Name, m.Description)
		}
		fmt.Fprintf(&sb, "- `%s` %s: %s\n", defenseHoneypots.Flag, defenseHoneypots.Name, defenseHoneypots.Description)
		sb.WriteString("\n#### Daemon flags\n\n")
		sb.WriteString("| Flag | Meaning |\n|---|---|\n")
		for _, f := range defenseDaemonFlags {
			fmt.Fprintf(&sb, "| `%s` | %s |\n", f.Flag, f.Meaning)
		}
		sb.WriteString("\n#### Alert record schema (NDJSON, one JSON object per line)\n\n")
		sb.WriteString("```json\n")
		sb.WriteString(`{"timestamp": <u64 ns>, "alert_type": "<string>", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "pid": <u32>, "context": <u64>, "details": "<string>", "anomaly_score": <f64>, "correlated_types": ["<string>"], "is_attack_chain": <bool>}`)
		sb.WriteString("\n```\n\n")
	}

	if input.Component == "" || input.Component == "offense" {
		sb.WriteString("### Offense rootkit loader (binary `offense`, clap name `aegis-shadow-offense`)\n\n")
		sb.WriteString("Long-running daemon: attaches eBPF rootkit programs, runs until Ctrl+C or C2 kill switch. Human-readable logs only. Root required.\n\n")
		sb.WriteString("#### Always-loaded base features (not flag-gated)\n\n")
		for _, f := range offenseBaseFeatures {
			fmt.Fprintf(&sb, "- %s\n", f)
		}
		sb.WriteString("\n#### Flag-gated feature groups\n\n")
		sb.WriteString("| Flag | Feature | Hook point | Risk notes |\n")
		sb.WriteString("|---|---|---|---|\n")
		for _, f := range offenseFeatures {
			fmt.Fprintf(&sb, "| `%s` | %s (%s) | %s | %s |\n", f.Flag, f.Description, f.ID, f.HookPoint, f.Risk)
		}
		sb.WriteString("\n#### Option flags\n\n")
		sb.WriteString("| Flag | Format | Meaning |\n|---|---|---|\n")
		for _, f := range offenseOptionFlags {
			fmt.Fprintf(&sb, "| `%s` | %s | %s |\n", f.Flag, f.Format, f.Meaning)
		}
		sb.WriteString("\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
