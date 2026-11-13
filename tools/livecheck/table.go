package livecheck

import "time"

// flagSurfaceTable maps every wrapped binary to the argv fragments the
// RedHands wrappers actually emit, and to the checks that verify them against
// the real binary. Each entry cites the wrapper package(s) it mirrors; when a
// wrapper changes its argv, the matching entry here must change with it.
//
// Check modes per binary were chosen from what the CLI supports:
//   - help-text assertion wherever `--help` (or the tool's equivalent)
//     enumerates its flags: all pinned RedHands-family release binaries
//     (clap/cobra-style), the projectdiscovery Go tools, nmap, tshark,
//     sqlmap, whatweb, impacket (argparse), certipy, john, hashcat.
//   - dry-parse assertion wherever flags are not reliably listed in help,
//     or to verify enum values and combined subcommand+flag argvs:
//     kubedagger-client (cobra prints "Error: unknown flag" but exits 0),
//     masscan (--echo), dig, ffuf, rustscan, chisel/ligolo dry runs.
//
// Placeholders follow the safe conventions: TEST-NET/loopback addresses,
// example.com, /dev/null, and paths that are only parsed, never dereferenced,
// because every invocation is terminated by a help/echo flag.
var flagSurfaceTable = []binaryChecks{
	// -------------------------------------------------------------------
	// KubeDagger (tools/kubedagger) — pinned release v0.5.0.
	// cobra-style client: unknown flags/commands print "Error: ..." on a
	// zero exit code, so subcommand+flag argvs are dry-parsed with --help.
	// -------------------------------------------------------------------
	{
		binary:   "kubedagger-client",
		wrappers: []string{"kubedagger"},
		help: []helpCheck{
			{
				name:     "root subcommands",
				helpArgs: []string{"--help"},
				want: []string{
					// Every subcommand word the wrappers emit as argv[0]
					// (mixed dash/underscore names are intentional — they
					// mirror the release binary's command list).
					"arp-spoof", "audit-filter", "bpf-ipc", "cert-sabotage",
					"cgroup-manip", "cloud", "container-log-c2",
					"coredump-suppress", "covert-channel", "crd-backdoor",
					"cri-tamper", "daemonset", "detection", "dns_exfil",
					"docker", "doh-c2", "election-disrupt", "escape",
					"etcd-steal", "evasion", "fault-inject", "fileless-exec",
					"fs_watch", "gitops-poison", "honeypot-detect", "k8s",
					"k8s-event-c2", "keyring", "keyring-mitm", "kubelet",
					"log-tamper", "meshbypass", "mitre", "netbypass",
					"network_discovery", "obs-poison", "pcap-blind",
					"pipe_prog", "pod-identity", "polymorph", "postgres",
					"proctree", "report", "sa-token", "sched-starve",
					"secrets", "sidecar-inject", "sig-bypass", "supply-chain",
					"syscall-bypass", "tcp-stego", "timeskew",
					"tls-intercept", "vap_backdoor", "veth-hijack",
					"webhook", "xdp-shell",
				},
			},
			{
				name:     "k8s discover flags",
				helpArgs: []string{"k8s", "discover", "--help"},
				want:     []string{"--namespace"},
			},
			{
				name:     "dns_exfil flags",
				helpArgs: []string{"dns_exfil", "--help"},
				want:     []string{"--file", "--domain", "--server"},
			},
			{
				name:     "evasion flags and mode enum",
				helpArgs: []string{"evasion", "--help"},
				want:     []string{"--mode", "cnative-sensor", "cnative-probe", "cnative-shield", "all"},
			},
			{
				name:     "network_discovery flags",
				helpArgs: []string{"network_discovery", "scan", "--help"},
				want:     []string{"--ip", "--port"},
			},
		},
		parse: []parseCheck{
			// Representative wrapper argvs (k8s_discover.go, dns_exfil.go,
			// evasion.go, network_discovery.go, sidecar_inject.go,
			// fileless_exec.go, sa_token.go, c2_channels.go,
			// arp_spoof.go, docker_ops.go, postgres.go, report.go).
			{name: "k8s discover", argv: []string{"k8s", "discover", "--namespace", "default"}},
			{name: "dns_exfil", argv: []string{"dns_exfil", "--file", "/dev/null", "--domain", "example.com", "--server", "192.0.2.53"}},
			{name: "evasion mode cnative-sensor", argv: []string{"evasion", "--mode", "cnative-sensor"}},
			{name: "evasion mode cnative-probe", argv: []string{"evasion", "--mode", "cnative-probe"}},
			{name: "evasion mode cnative-shield", argv: []string{"evasion", "--mode", "cnative-shield"}},
			{name: "evasion mode all", argv: []string{"evasion", "--mode", "all"}},
			{name: "network_discovery scan", argv: []string{"network_discovery", "scan", "--ip", "192.0.2.0/24", "--port", "443"}},
			{name: "network_discovery get", argv: []string{"network_discovery", "get"}},
			{name: "sidecar-inject", argv: []string{"sidecar-inject", "--pod", "nginx"}},
			{name: "fileless-exec", argv: []string{"fileless-exec", "--payload", "curl"}},
			{name: "sa-token", argv: []string{"sa-token", "--action", "list"}},
			{name: "k8s-event-c2", argv: []string{"k8s-event-c2"}},
			{name: "container-log-c2", argv: []string{"container-log-c2", "--container", "app"}},
			{name: "doh-c2", argv: []string{"doh-c2", "--domain", "example.com"}},
			{name: "arp-spoof", argv: []string{"arp-spoof", "--victim-ip", "192.0.2.10", "--gateway-ip", "192.0.2.1"}},
			{name: "docker list", argv: []string{"docker", "list"}},
			{name: "cloud exfil", argv: []string{"cloud", "exfil"}},
			{name: "cloud meta", argv: []string{"cloud", "meta"}},
			{name: "postgres put", argv: []string{"postgres", "put"}},
			{name: "report generate", argv: []string{"report", "generate", "--events", "/dev/null"}},
			{name: "mitre export", argv: []string{"mitre", "export"}},
			{name: "secrets harvest", argv: []string{"secrets", "harvest"}},
			{name: "k8s abuse", argv: []string{"k8s", "abuse"}},
			{name: "proctree get", argv: []string{"proctree", "get"}},
			{name: "fs_watch add", argv: []string{"fs_watch", "add", "/tmp"}},
			{name: "pipe_prog put", argv: []string{"pipe_prog", "put"}},
			{name: "detection generate", argv: []string{"detection", "generate"}},
		},
	},
	{
		// kubedagger-server (server.go): --events always, --scope/--malleable/
		// --webui/--rate-limit/--psk optional. Go stdlib flag: -h prints
		// usage and exits 0.
		binary:   "kubedagger-server",
		wrappers: []string{"kubedagger"},
		help: []helpCheck{
			{
				name:     "server flags",
				helpArgs: []string{"-h"},
				want:     []string{"-events", "-scope", "-malleable", "-webui", "-rate-limit", "-psk", "-key", "-listen"},
			},
		},
		parse: []parseCheck{
			{name: "server argv", argv: []string{"--events", "/dev/null", "--scope", "lab", "--webui", "127.0.0.1:18080", "--rate-limit", "10", "--psk", "test"}, terminator: "-h"},
		},
	},
	{
		// kubedagger-operator (operator.go): Go stdlib global flags BEFORE
		// the positional subcommand. -h exits 0. The dry-parse dials the
		// (loopback, refused) management address after parsing flags, which
		// proves the flags parsed cleanly.
		binary:   "kubedagger-operator",
		wrappers: []string{"kubedagger"},
		help: []helpCheck{
			{
				name:     "operator global flags",
				helpArgs: []string{"-h"},
				want:     []string{"-key", "-addr"},
			},
		},
		parse: []parseCheck{
			{name: "agents subcommand", argv: []string{"-key", "test", "-addr", "127.0.0.1:1", "agents"}, terminator: "--help"},
			{name: "shell subcommand", argv: []string{"-key", "test", "-addr", "127.0.0.1:1", "shell", "agent-1", "id"}, terminator: "--help"},
			{name: "module subcommand", argv: []string{"-key", "test", "-addr", "127.0.0.1:1", "module", "agent-1", "keylog"}, terminator: "--help"},
			{name: "status subcommand", argv: []string{"-key", "test", "-addr", "127.0.0.1:1", "status", "task-1"}, terminator: "--help"},
			{name: "tasks subcommand", argv: []string{"-key", "test", "-addr", "127.0.0.1:1", "tasks", "agent-1"}, terminator: "--help"},
		},
	},

	// -------------------------------------------------------------------
	// Barzakh (tools/barzakh) — pinned release v0.7.0. clap-style.
	// -------------------------------------------------------------------
	{
		binary:   "barzakh-scanner",
		wrappers: []string{"barzakh"},
		help: []helpCheck{
			{
				name:     "root subcommands",
				helpArgs: []string{"--help"},
				want:     []string{"scan", "baseline", "report", "validate", "detectors", "info", "fuzz", "range", "history", "kb", "intel", "ml", "serve"},
			},
			{
				name:     "scan flags",
				helpArgs: []string{"scan", "--help"},
				want:     []string{"--target", "--baseline", "--scan-types", "--json", "--report", "--rules-dir", "--yara", "--history", "--ml"},
			},
			{
				name:     "scan report format enum",
				helpArgs: []string{"scan", "--help"},
				want:     []string{"json", "html", "markdown", "sarif", "csv", "ecs", "cef", "leef"},
			},
			{
				name:     "report flags",
				helpArgs: []string{"report", "--help"},
				want:     []string{"--target", "--baseline", "--output", "--format"},
			},
			{
				name:     "validate flags",
				helpArgs: []string{"validate", "--help"},
				want:     []string{"--corpus", "--baseline", "--json"},
			},
		},
		parse: []parseCheck{
			// scan.go, report.go, manifest_validate.go (supported subset),
			// detectors.go, baseline.go, fuzz.go, intel.go, kb.go,
			// history.go, ml.go, range.go.
			{name: "scan", argv: []string{"scan", "--target", "/dev/null", "--json", "--report", "/dev/null", "--format", "sarif"}},
			{name: "scan format csv", argv: []string{"scan", "--target", "/dev/null", "--format", "csv"}},
			{name: "report", argv: []string{"report", "--target", "/dev/null", "--baseline", "/dev/null", "--output", "/dev/null", "--format", "ecs"}},
			{name: "validate corpus+baseline", argv: []string{"validate", "--corpus", "/dev/null", "--baseline", "/dev/null"}},
			{name: "detectors info (positional name)", argv: []string{"detectors", "info", "bootkit"}},
			{name: "detectors list", argv: []string{"detectors", "list"}},
			{name: "baseline create", argv: []string{"baseline", "create", "--target", "/dev/null"}},
			{name: "baseline show", argv: []string{"baseline", "show"}},
			{name: "fuzz", argv: []string{"fuzz", "--iterations", "1", "--output-dir", "/tmp", "--mutate", "--protocol", "dhcpv6", "--json"}},
			{name: "intel feeds", argv: []string{"intel", "feeds"}},
			{name: "kb import", argv: []string{"kb", "import", "--input", "/dev/null", "--db", "/dev/null"}},
			{name: "kb list", argv: []string{"kb", "list"}},
			{name: "history trends", argv: []string{"history", "trends", "--db", "/dev/null"}},
			{name: "history list", argv: []string{"history", "list"}},
			{name: "ml evaluate", argv: []string{"ml", "evaluate", "--corpus", "/dev/null", "--model", "/dev/null"}},
			{name: "range up", argv: []string{"range", "up", "--suite", "smoke", "--range-dir", "/tmp", "--dry-run"}},
			// manifest_validate.go passes --manifest/--strict/--split,
			// which the pinned barzakh-scanner v0.7.0 does not accept
			// (its validate only has --corpus/--baseline/--json). Tracked
			// as known drift until the wrapper or the release pin moves.
			{
				name:       "manifest validate",
				argv:       []string{"validate", "--corpus", "/dev/null", "--manifest", "/dev/null", "--strict", "--split", "train"},
				knownDrift: "tools/barzakh/manifest_validate.go wraps a scanner CLI newer than the pinned v0.7.0 release; fix the wrapper or bump the dependency pin",
			},
		},
	},
	{
		binary:   "barzakh-adversary",
		wrappers: []string{"barzakh"},
		help: []helpCheck{
			{
				name:     "root subcommands",
				helpArgs: []string{"--help"},
				want:     []string{"generate", "list", "corpus", "validate", "qemu", "esp", "inject-single", "scenario", "robustness"},
			},
			{
				name:     "generate flags",
				helpArgs: []string{"generate", "--help"},
				want:     []string{"--payload", "--output", "--arch"},
			},
			{
				name:     "esp build flags",
				helpArgs: []string{"esp", "build", "--help"},
				want:     []string{"--payload", "--output", "--size"},
			},
			{
				name:     "inject-single flags",
				helpArgs: []string{"inject-single", "--help"},
				want:     []string{"--input", "--output", "--payload", "--arch"},
			},
			{
				name:     "adversary validate flags",
				helpArgs: []string{"validate", "--help"},
				want:     []string{"--corpus", "--json"},
			},
		},
		parse: []parseCheck{
			// list.go, generate.go, corpus.go, adversary_validate.go,
			// scenario.go, qemu.go, inject.go, robustness.go.
			{name: "list", argv: []string{"list"}},
			{name: "generate", argv: []string{"generate", "--payload", "test", "--output", "/dev/null", "--arch", "x64"}},
			{name: "esp build", argv: []string{"esp", "build", "--payload", "test", "--output", "/dev/null", "--size", "100M"}},
			{name: "inject-single", argv: []string{"inject-single", "--input", "/dev/null", "--output", "/dev/null", "--payload", "test"}},
			{name: "validate", argv: []string{"validate", "--corpus", "/dev/null", "--json"}},
			{name: "scenario", argv: []string{"scenario", "list"}},
			{name: "qemu run", argv: []string{"qemu", "run", "--esp", "/dev/null"}},
			{name: "corpus", argv: []string{"corpus", "--output", "/dev/null"}},
			{name: "robustness", argv: []string{"robustness", "--filter", "all"}},
		},
	},
	{
		// barzakh-server (server.go): --db, --payloads-dir, --port, --api-key.
		// The v0.7.0 release prints its flag surface in --help prose.
		binary:   "barzakh-server",
		wrappers: []string{"barzakh"},
		help: []helpCheck{
			{
				name:     "server flags",
				helpArgs: []string{"--help"},
				want:     []string{"--port", "--db", "--payloads-dir", "--api-key"},
			},
		},
		parse: []parseCheck{
			{name: "server argv", argv: []string{"--db", "/dev/null", "--payloads-dir", "/tmp", "--port", "18420", "--api-key", "test"}},
		},
	},

	// -------------------------------------------------------------------
	// Telecom / StaticZero (tools/telecom) — pinned release v0.5.0.
	// -------------------------------------------------------------------
	{
		binary:   "staticzero-defense",
		wrappers: []string{"telecom"},
		help: []helpCheck{
			{
				name:     "defense flags",
				helpArgs: []string{"--help"},
				want: []string{
					"--bpf-path", "--config", "--doctor", "--modules",
					"--telecom-detect", "--telecom-advanced",
					"--telecom-5g-defense", "--satellite-defense",
					"--rf-defense", "--all", "--json",
					"--correlation-window",
				},
			},
		},
		parse: []parseCheck{
			// doctor.go: --doctor --json [--bpf-path].
			{name: "doctor", argv: []string{"--doctor", "--json"}},
			// defense_start.go: group flag + --json [--modules] [--config]
			// [--correlation-window].
			{name: "defense all", argv: []string{"--all", "--json", "--modules", "1,2", "--correlation-window", "30"}},
			{name: "defense telecom-detect", argv: []string{"--telecom-detect", "--json"}},
			{name: "defense telecom-advanced", argv: []string{"--telecom-advanced", "--json"}},
			{name: "defense telecom-5g-defense", argv: []string{"--telecom-5g-defense", "--json"}},
			{name: "defense satellite-defense", argv: []string{"--satellite-defense", "--json"}},
			{name: "defense rf-defense", argv: []string{"--rf-defense", "--json"}},
		},
	},
	{
		binary:   "staticzero-offense",
		wrappers: []string{"telecom"},
		help: []helpCheck{
			{
				name:     "offense flags",
				helpArgs: []string{"--help"},
				want: []string{
					"--bpf-path", "--enable-telecom", "--enable-telecom-advanced",
					"--enable-5g-advanced", "--enable-satellite", "--enable-rf",
					"--all", "--target-imsi", "--gtp-iface", "--ims-iface",
					"--wifi-iface", "--sbi-iface", "--sdr-iface", "--sat-iface",
					"--uav-iface", "--wpan-iface", "--fronthaul-iface",
				},
			},
		},
		parse: []parseCheck{
			// offense_start.go: group flags + --all + iface/target flags.
			{name: "offense telecom", argv: []string{"--enable-telecom", "--gtp-iface", "eth0", "--target-imsi", "001011234567891"}},
			{name: "offense all", argv: []string{"--all", "--bpf-path", "/dev/null", "--wifi-iface", "wlan0"}},
		},
	},
	{
		binary:   "modem-firmware",
		wrappers: []string{"telecom"},
		help: []helpCheck{
			{
				name:     "subcommands",
				helpArgs: []string{"--help"},
				want:     []string{"extract", "analyze", "patch", "diff", "nv-dump", "monitor"},
			},
			{
				name:     "analyze flags",
				helpArgs: []string{"analyze", "--help"},
				want:     []string{"--target", "--chipset", "--report"},
			},
			{
				name:     "extract flags",
				helpArgs: []string{"extract", "--help"},
				want:     []string{"--image", "--chipset", "--output"},
			},
			{
				name:     "patch flags",
				helpArgs: []string{"patch", "--help"},
				want:     []string{"--image", "--patchfile", "--output"},
			},
			{
				name:     "monitor flags",
				helpArgs: []string{"monitor", "--help"},
				want:     []string{"--device", "--protocol"},
			},
		},
		parse: []parseCheck{
			// firmware.go, firmware_patch.go, firmware_monitor.go.
			{name: "analyze", argv: []string{"analyze", "--target", "/dev/null", "--chipset", "qualcomm", "--report", "/dev/null"}},
			{name: "extract", argv: []string{"extract", "--image", "/dev/null", "--chipset", "qualcomm", "--output", "/tmp"}},
			{name: "diff", argv: []string{"diff", "--old", "/dev/null", "--new", "/dev/null", "--chipset", "qualcomm"}},
			{name: "nv-dump", argv: []string{"nv-dump", "--image", "/dev/null", "--output", "/dev/null"}},
			{name: "patch", argv: []string{"patch", "--image", "/dev/null", "--patchfile", "/dev/null", "--output", "/dev/null"}},
			{name: "monitor", argv: []string{"monitor", "--device", "/dev/null", "--protocol", "diag"}},
		},
	},
	{
		binary:   "sdr-bridge",
		wrappers: []string{"telecom"},
		help: []helpCheck{
			{
				name:     "sdr flags",
				helpArgs: []string{"--help"},
				want: []string{
					"--sdr-type", "--device-id", "--frequency", "--sample-rate",
					"--gain", "--bandwidth", "--mode", "--scan-bands",
				},
			},
			{
				name:     "sdr-type enum",
				helpArgs: []string{"--help"},
				want:     []string{"hackrf", "bladerf", "usrp", "rtlsdr", "limesdr"},
			},
			{
				name:     "mode enum",
				helpArgs: []string{"--help"},
				want:     []string{"scan", "capture", "inject", "relay", "selftest-tx"},
			},
		},
		parse: []parseCheck{
			// sdr.go scan argv, sdr_modes.go selftest-tx argv.
			{name: "scan", argv: []string{"--mode", "scan", "--sdr-type", "hackrf", "--frequency", "2620000000", "--sample-rate", "20000000", "--gain", "40", "--bandwidth", "20000000", "--device-id", "0", "--scan-bands", "all-lte"}},
			{name: "selftest-tx", argv: []string{"--mode", "selftest-tx", "--frequency", "2620000000", "--sample-rate", "20000000", "--gain", "20"}},
		},
	},
	{
		// protocol-correlator (correlator_start.go) is not part of the
		// pinned artifact set; it is checked whenever it is on PATH.
		binary:   "protocol-correlator",
		wrappers: []string{"telecom"},
		parse: []parseCheck{
			{name: "correlator argv", argv: []string{"--ingest-port", "17890", "--window-ms", "100", "--threshold", "0.5", "--output", "json", "--max-events", "100"}},
		},
	},

	// -------------------------------------------------------------------
	// Aegis-Shadow (tools/aegis) — pinned release v0.1.1.
	// -------------------------------------------------------------------
	{
		binary:   "aegis-shadow-defense",
		wrappers: []string{"aegis"},
		help: []helpCheck{
			{
				name:     "defense daemon flags",
				helpArgs: []string{"--help"},
				want: []string{
					// defense_start.go non-module flags.
					"--all-modules", "--json-stdout", "--threshold",
					"--calibration-period", "--config", "--enable-ml",
					"--auto-detach", "--auto-contain", "--honeypots",
					// The 15 per-module flags (modules.go catalog).
					"--ghost-maps", "--syscall-latency", "--bytecode-check",
					"--hidden-process", "--suspicious-hooks",
					"--prog-inventory", "--syscall-anomaly",
					"--net-baseline", "--memfd-detect", "--map-audit",
					"--tracepoint-monitor", "--cross-reference",
					"--hw-perf-counters", "--verifier-analysis",
					"--memory-forensics",
				},
			},
		},
		parse: []parseCheck{
			{name: "all modules", argv: []string{"--all-modules", "--json-stdout"}},
			{name: "selected modules", argv: []string{"--ghost-maps", "--syscall-latency", "--bytecode-check", "--json-stdout", "-t", "2", "--calibration-period", "60", "--enable-ml"}},
		},
	},
	{
		binary:   "aegis-shadow-offense",
		wrappers: []string{"aegis"},
		help: []helpCheck{
			{
				name:     "offense loader flags",
				helpArgs: []string{"--help"},
				want: []string{
					// offense_start.go: --enable-<feature> for every name in
					// validOffenseFeatureNames, plus the positional flags.
					"--iface", "--hide-pid", "--obfuscate-inode",
					"--monitor-tty", "--spoof-ppid", "--timestomp",
					"--pin-maps", "--wipe-bytecode",
					"--enable-netns-hide", "--enable-bpf-cloak",
					"--enable-module-mask", "--enable-memfd",
					"--enable-syslog-strip", "--enable-icmp-exfil",
					"--enable-socket-clone", "--enable-cred-relay",
					"--enable-container-probe", "--enable-kprobe-evasion",
					"--enable-tail-calls", "--enable-ftrace-blind",
					"--enable-bpf-iter-abuse", "--enable-vdso-hook",
					"--enable-shm-covert", "--enable-uffd-inject",
					"--enable-coredump-suppress", "--enable-isn-covert",
					"--enable-ipv6-ext", "--enable-arp-poison",
					"--enable-port-knock", "--enable-bgp-hijack",
					"--enable-dr-abuse", "--enable-pmc-covert",
					"--enable-tsc-sidechan", "--enable-audit-kill",
					"--enable-inode-slack", "--enable-journal-manip",
					"--enable-proc-spoof", "--enable-initramfs",
					"--enable-modsign-bypass", "--enable-polymorphic",
					"--enable-phantom-stack", "--enable-container-lateral",
					"--enable-dma-covert", "--enable-behavioral-ai",
					"--enable-supply-chain", "--enable-bpf-parasitism",
					"--enable-kernel-object", "--enable-network-stealth",
					"--enable-persistence2", "--enable-deadman-switch",
				},
			},
		},
	},
	{
		binary:   "aegis-c2",
		wrappers: []string{"aegis"},
		help: []helpCheck{
			{
				name:     "c2 sender flags",
				helpArgs: []string{"--help"},
				want:     []string{"--target", "--port", "--command", "--key"},
			},
			{
				name:     "c2 command enum",
				helpArgs: []string{"--help"},
				want:     []string{"hide-pid", "unhide-pid", "obfuscate-file", "exfil", "kill-switch"},
			},
		},
		parse: []parseCheck{
			// c2_send.go: --target --command --port [--arg].
			{name: "c2 send", argv: []string{"--target", "192.0.2.10", "--command", "hide-pid", "--port", "53"}},
		},
	},

	// -------------------------------------------------------------------
	// Metasploit (tools/msf). msfvenom only: msfconsole -q -r boots an
	// interactive console (10-60s) and would execute resource-file
	// commands, so it is deliberately not invoked here; its argv
	// (-q -r <file>) is documented in tools/msf/resource_run.go.
	// -------------------------------------------------------------------
	{
		binary:   "msfvenom",
		wrappers: []string{"msf"},
		timeout:  60 * time.Second,
		help: []helpCheck{
			{
				name:     "payload generation flags",
				helpArgs: []string{"--help"},
				want: []string{
					"-p", "-f", "-o", "-a", "--platform", "-e", "-i", "-b",
					"-n", "--smallest", "--keep",
				},
			},
		},
		parse: []parseCheck{
			// payload_list.go: msfvenom --list <kind>. Read-only.
			{name: "list payloads", argv: []string{"--list", "payloads"}, terminator: "--help"},
			{name: "payload generate", argv: []string{"-p", "linux/x86/shell_reverse_tcp", "-f", "elf", "-o", "/dev/null", "-a", "x86", "--platform", "linux", "--smallest", "--keep"}, terminator: "--help"},
		},
	},

	// -------------------------------------------------------------------
	// nmap (tools/scan/nmap). nmap -h prints the option summary and exits 0
	// (nmap.cc: case 'h': printusage(); exit(0)); --help maps to 'h'.
	// -------------------------------------------------------------------
	{
		binary:   "nmap",
		wrappers: []string{"nmap"},
		help: []helpCheck{
			{
				name:     "wrapper flags",
				helpArgs: []string{"-h"},
				want: []string{
					// port_scan.go / service_detect.go / os_detect.go / vuln_scan.go.
					"-sS", "-sT", "-sU", "-sV", "-O", "-A",
					"--version-intensity", "--script", "-oX", "--top-ports",
					"-T<0-5>", "-p <port ranges>",
				},
			},
		},
		parse: []parseCheck{
			// Dry-parse the port_scan.go argv; -h terminates before any
			// target resolution or probing.
			{name: "port scan syn", argv: []string{"-oX", "-", "-sS", "-T4", "-p", "1-100", "192.0.2.1"}, terminator: "-h"},
			{name: "service detect", argv: []string{"-oX", "-", "-sV", "--version-intensity", "5", "-p", "443", "192.0.2.1"}, terminator: "-h"},
			{name: "vuln scan", argv: []string{"-oX", "-", "-sV", "--script", "vuln", "192.0.2.1"}, terminator: "-h"},
		},
	},

	// -------------------------------------------------------------------
	// masscan (tools/scan/masscan). --help prints usage and exits 1
	// (masscan.c: masscan_help(); exit(1)); --echo parses the whole argv,
	// echoes the config and exits without scanning.
	// -------------------------------------------------------------------
	{
		binary:   "masscan",
		wrappers: []string{"scan"},
		help: []helpCheck{
			{
				name:       "help mentions key options",
				helpArgs:   []string{"--help"},
				acceptExit: []int{1},
				want:       []string{"--adapter-ip", "--echo", "-p"},
			},
		},
		parse: []parseCheck{
			// masscan.go argv with the --echo safe terminator.
			{name: "masscan argv", argv: []string{"192.0.2.0/24", "-p", "443", "--rate", "1000", "--banners", "--exclude", "192.0.2.255", "-e", "lo", "--wait", "1", "--retries", "1", "--adapter-ip", "192.0.2.1", "--open-only", "-oX", "-"}, terminator: "--echo"},
			{name: "top-ports", argv: []string{"192.0.2.1", "--top-ports", "10", "-oJ", "-"}, terminator: "--echo"},
		},
	},

	// -------------------------------------------------------------------
	// rustscan (tools/scan/rustscan). clap-style: -h exits 0.
	// -------------------------------------------------------------------
	{
		binary:   "rustscan",
		wrappers: []string{"scan"},
		help: []helpCheck{
			{
				name:     "rustscan flags",
				helpArgs: []string{"-h"},
				want:     []string{"-a", "-p", "--range", "-b", "-t", "--tries", "--top", "-g", "--ulimit", "--no-nmap", "--scan-order", "--accessible"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Recon (tools/recon).
	// -------------------------------------------------------------------
	{
		binary:   "subfinder",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:     "subfinder flags",
				helpArgs: []string{"-h"},
				want:     []string{"-d", "-silent", "-recursive", "-sources", "-exclude-sources", "-all", "-rl", "-r", "-timeout", "-config", "-oJ"},
			},
		},
	},
	{
		binary:   "amass",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:     "amass enum flags",
				helpArgs: []string{"enum", "-h"},
				want:     []string{"-d", "-whois", "-org", "-addr", "-asn", "-cidr", "-passive", "-brute", "-max-depth", "-config", "-timeout"},
			},
		},
	},
	{
		binary:   "gau",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:     "gau flags",
				helpArgs: []string{"--help"},
				want:     []string{"--providers", "--subs", "--blacklist", "--mt", "--fc", "--from", "--to", "--threads", "--verbose", "--json", "--fp"},
			},
		},
	},
	{
		binary:   "waybackurls",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:     "waybackurls flags",
				helpArgs: []string{"-h"},
				want:     []string{"-no-subs", "-get-versions"},
			},
		},
	},
	{
		binary:   "arjun",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:     "arjun flags",
				helpArgs: []string{"-h"},
				want:     []string{"-u", "-m", "--headers", "-w", "-t", "-d", "--include", "--stable", "--passive", "-oJ", "-c", "-T"},
			},
		},
	},
	{
		binary:   "dig",
		wrappers: []string{"recon"},
		help: []helpCheck{
			{
				name:       "dig flags",
				helpArgs:   []string{"-h"},
				acceptExit: []int{0, 1},
				want:       []string{"+short", "+trace", "+tcp", "+noall", "AXFR"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Web (tools/web).
	// -------------------------------------------------------------------
	{
		binary:   "httpx",
		wrappers: []string{"web"},
		help: []helpCheck{
			{
				name:     "httpx flags",
				helpArgs: []string{"-h"},
				want:     []string{"-silent", "-ports", "-status-code", "-title", "-tech-detect", "-follow-redirects", "-threads", "-cdn", "-jarm", "-include-response", "-content-length", "-mc", "-hash"},
			},
		},
	},
	{
		binary:   "katana",
		wrappers: []string{"web"},
		help: []helpCheck{
			{
				name:     "katana flags",
				helpArgs: []string{"-h"},
				want:     []string{"-u", "-silent", "-d", "-jc", "-headless", "-fs", "-c", "-aff", "-kf", "-ef", "-em", "-f", "-rl", "-proxy"},
			},
		},
	},
	{
		binary:   "whatweb",
		wrappers: []string{"web"},
		help: []helpCheck{
			{
				name:     "whatweb flags",
				helpArgs: []string{"--help"},
				want:     []string{"--color", "--no-errors", "-a", "-v", "--proxy", "--cookie", "--header", "-p", "-U", "--max-threads", "--url-prefix", "--url-suffix"},
			},
		},
	},
	{
		// nikto has no dedicated help flag: bare `nikto` prints the usage
		// text (including -nointeractive, -Format and friends) and exits
		// with a non-zero status.
		binary:   "nikto",
		wrappers: []string{"web"},
		help: []helpCheck{
			{
				name:       "nikto usage",
				helpArgs:   []string{},
				acceptExit: []int{0, 1, 2, 3, 4},
				want:       []string{"-h", "-nointeractive", "-Format", "-ssl", "-Tuning", "-Plugins", "-timeout", "-useproxy", "-mutate", "-evasion", "-useragent", "-id", "-Cgidirs", "-no404"},
			},
		},
	},
	{
		binary:   "testssl.sh",
		wrappers: []string{"web"},
		help: []helpCheck{
			{
				name:       "testssl usage",
				helpArgs:   []string{},
				acceptExit: []int{0, 1},
				want:       []string{"--color", "--starttls", "--severity", "--parallel", "--fast", "--sneaky", "--ip", "--openssl"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Fuzz (tools/fuzz).
	// -------------------------------------------------------------------
	{
		binary:   "ffuf",
		wrappers: []string{"fuzz"},
		help: []helpCheck{
			{
				name:     "ffuf flags",
				helpArgs: []string{"-h"},
				want:     []string{"-u", "-w", "-s", "-X", "-H", "-d", "-mc", "-fc", "-fs", "-t", "-rate", "-e", "-ac", "-recursion", "-recursion-depth", "-ml"},
			},
		},
	},
	{
		binary:   "feroxbuster",
		wrappers: []string{"fuzz"},
		help: []helpCheck{
			{
				name:     "feroxbuster flags",
				helpArgs: []string{"--help"},
				want:     []string{"-u", "--no-state", "-q", "-w", "-t", "-d", "-s", "-C", "-S", "-W", "-x", "-n", "-T", "-p"},
			},
		},
	},
	{
		binary:   "gobuster",
		wrappers: []string{"fuzz"},
		help: []helpCheck{
			{
				name:     "dns mode flags",
				helpArgs: []string{"dns", "--help"},
				want:     []string{"--domain", "--wildcard", "-w", "-q", "--no-color", "-t", "--delay"},
			},
			{
				name:     "dir mode flags",
				helpArgs: []string{"dir", "--help"},
				want:     []string{"-u", "-w", "-q", "--no-color", "-x", "-b", "-s", "-t", "-r", "-k", "--proxy", "-c", "-H", "-a", "-U", "-P", "--delay"},
			},
			{
				name:     "vhost mode flags",
				helpArgs: []string{"vhost", "--help"},
				want:     []string{"-u", "--domain", "--append-domain", "-w", "-q", "--no-color"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Vulnerability (tools/vuln).
	// -------------------------------------------------------------------
	{
		binary:   "nuclei",
		wrappers: []string{"vuln"},
		help: []helpCheck{
			{
				name:     "nuclei flags",
				helpArgs: []string{"-h"},
				want:     []string{"-u", "-silent", "-nc", "-t", "-severity", "-tags", "-exclude-tags", "-rl", "-bulk-size", "-proxy", "-iserver", "-headless", "-sr", "-nt", "-as", "-id"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Exploit (tools/exploit).
	// -------------------------------------------------------------------
	{
		binary:   "sqlmap",
		wrappers: []string{"exploit"},
		timeout:  60 * time.Second,
		help: []helpCheck{
			{
				name:     "sqlmap basic options",
				helpArgs: []string{"--help"},
				want:     []string{"--batch", "-u", "--data", "--cookie", "--level", "--risk", "--dbs", "--tables", "--columns", "--dump", "--dbms", "--random-agent", "--current-user", "--current-db", "--flush-session"},
			},
			{
				name:     "sqlmap advanced options",
				helpArgs: []string{"-hh"},
				want:     []string{"--disable-coloring", "-X METHOD", "--tamper", "--forms", "--crawl", "--delay", "--timeout", "--retries", "--threads", "--headers", "--proxy", "--sql-query", "--fresh-queries", "--time-sec"},
			},
		},
		parse: []parseCheck{
			// sqlmap.go argv; -hh prints advanced help and exits 0 after a
			// clean parse (unknown options abort with exit 2 first).
			{name: "sqlmap argv", argv: []string{"-u", "http://192.0.2.1/x", "--batch", "--disable-coloring", "--data", "a=1", "--level", "2", "--risk", "1", "--dbms", "mysql", "--random-agent", "--tamper", "space2comment", "--forms", "--crawl", "1"}, terminator: "-hh"},
		},
	},
	{
		binary:   "impacket-secretsdump",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "secretsdump flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-just-dc", "-just-dc-user", "-outputfile", "-system", "-sam", "-ntds"},
			},
		},
	},
	{
		binary:   "impacket-psexec",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "psexec flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-target-ip", "-port", "-codec", "-file"},
			},
		},
	},
	{
		binary:   "impacket-ntlmrelayx",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "ntlmrelayx flags",
				helpArgs: []string{"--help"},
				want:     []string{"-t", "-smb2support", "-tf", "-ip", "-wh", "-socks", "-c"},
			},
		},
	},
	{
		binary:   "impacket-smbclient",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "smbclient flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-target-ip", "-port", "-inputfile", "-outputfile", "-no-pass"},
			},
		},
	},
	{
		binary:   "impacket-wmiexec",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "wmiexec flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-target-ip", "-codec", "-share", "-nooutput"},
			},
		},
	},
	{
		binary:   "impacket-dcomexec",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "dcomexec flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-codec", "-object"},
			},
		},
	},
	{
		binary:   "impacket-getTGT",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "getTGT flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-service"},
			},
		},
	},
	{
		binary:   "impacket-getST",
		wrappers: []string{"impacket"},
		help: []helpCheck{
			{
				name:     "getST flags",
				helpArgs: []string{"--help"},
				want:     []string{"-hashes", "-dc-ip", "-spn", "-impersonate", "-altservice"},
			},
		},
	},
	{
		binary:   "certipy",
		wrappers: []string{"certipy"},
		help: []helpCheck{
			{
				name:     "certipy subcommands",
				helpArgs: []string{"-h"},
				want:     []string{"find", "auth", "forge", "relay", "req", "shadow"},
			},
			{
				name:     "find flags",
				helpArgs: []string{"find", "-h"},
				want:     []string{"-u", "-p", "-target", "-dc-ip", "-ca"},
			},
			{
				name:     "req flags",
				helpArgs: []string{"req", "-h"},
				want:     []string{"-ca", "-template", "-u", "-p", "-target"},
			},
			{
				name:     "shadow flags",
				helpArgs: []string{"shadow", "-h"},
				want:     []string{"-account", "-u", "-p", "-target"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Tunnel (tools/tunnel).
	// -------------------------------------------------------------------
	{
		binary:   "chisel",
		wrappers: []string{"tunnel"},
		help: []helpCheck{
			{
				name:     "server flags",
				helpArgs: []string{"server", "--help"},
				want:     []string{"--host", "--port", "--key", "--auth", "--reverse", "--socks5"},
			},
			{
				name:     "client flags",
				helpArgs: []string{"client", "--help"},
				want:     []string{"--auth"},
			},
		},
	},
	{
		binary:   "ligolo-proxy",
		wrappers: []string{"tunnel"},
		help: []helpCheck{
			{
				name:     "proxy flags",
				helpArgs: []string{"--help"},
				want:     []string{"-laddr", "-selfcert", "-certfile", "-keyfile"},
			},
		},
	},

	// -------------------------------------------------------------------
	// Crack (tools/crack).
	// -------------------------------------------------------------------
	{
		binary:   "john",
		wrappers: []string{"crack"},
		help: []helpCheck{
			{
				// john --list=formats is the read-only invocation the
				// formats.go wrapper makes; it exits 0 and prints the
				// accepted --format values.
				name:     "format list",
				helpArgs: []string{"--list=formats"},
				want:     []string{"raw-md5"},
			},
			{
				// Bare john prints the full options summary.
				name:       "john options",
				helpArgs:   []string{},
				acceptExit: []int{0, 1},
				want:       []string{"--format", "--wordlist", "--show"},
			},
		},
	},
	{
		binary:   "hashcat",
		wrappers: []string{"crack"},
		help: []helpCheck{
			{
				name:       "hashcat flags",
				helpArgs:   []string{"-h"},
				acceptExit: []int{0, 1},
				want:       []string{"-m", "-a", "--show", "--potfile-path", "-b"},
			},
		},
	},

	// -------------------------------------------------------------------
	// tshark (tools/analysis).
	// -------------------------------------------------------------------
	{
		binary:   "tshark",
		wrappers: []string{"tshark"},
		help: []helpCheck{
			{
				name:       "tshark flags",
				helpArgs:   []string{"-h"},
				acceptExit: []int{0, 1},
				want:       []string{"-r", "-q", "-z", "-Y", "-T", "fields", "-i", "-f", "-e"},
			},
		},
		parse: []parseCheck{
			// extract.go / follow.go / stats.go / read.go argvs against a
			// nonexistent capture file: option parsing and file open errors
			// happen before any capture; --version terminates.
			{name: "read", argv: []string{"-r", "/nonexistent.pcap"}, terminator: "-v"},
			{name: "extract fields", argv: []string{"-r", "/nonexistent.pcap", "-T", "fields", "-e", "ip.src"}, terminator: "-v"},
			{name: "stats", argv: []string{"-r", "/nonexistent.pcap", "-q", "-z", "conv,ip", "-Y", "ip"}, terminator: "-v"},
			{name: "follow tcp", argv: []string{"-r", "/nonexistent.pcap", "-q", "-z", "follow,tcp,ascii,0"}, terminator: "-v"},
		},
	},
}
