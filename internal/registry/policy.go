package registry

import "github.com/yasindce1998/redhands/pkg/mcp"

// Built-in policies are reviewed by capability, not inferred from tool names.
// Anything absent stays approval-required, including mixed-mode tool wrappers.
func builtinPolicies() map[string]mcp.ToolPolicy {
	policies := make(map[string]mcp.ToolPolicy)
	for _, name := range []string{
		"redhands_health", "targetdb_list_hosts", "targetdb_query_findings", "targetdb_list_creds",
		"engagement_list", "loot_list", "loot_search", "credstore_search", "evidence_list",
		"report_sarif", "report_executive", "report_compliance", "correlation_analyze",
		"attackgraph_path", "attackgraph_export", "barzakh_list",
		"hashcat_show", "john_show", "john_formats", "tshark_read", "tshark_stats", "tshark_extract", "tshark_follow",
		// Barzakh: pure listings, corpus analysis, and intel queries.
		"barzakh_detectors", "barzakh_validate", "barzakh_intel",
		"barzakh_history", "barzakh_manifest_validate", "barzakh_info",
		// Aegis-Shadow: read-only alert analysis, catalog, and config reads.
		"aegis_alerts_parse", "aegis_alerts_tail", "aegis_modules_list", "aegis_defense_config_read",
		// StaticZero: read-only preflight and defense-engine queries.
		"telecom_doctor", "telecom_threats", "telecom_alerts", "telecom_stats",
	} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true}
	}
	for _, name := range []string{"mitre_lookup", "risk_score_calculate"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, Cacheable: true}
	}
	for _, name := range []string{"targetdb_add_host", "targetdb_add_finding", "targetdb_add_cred", "engagement_create", "engagement_switch", "loot_add", "credstore_add", "attackgraph_build"} {
		policies[name] = mcp.ToolPolicy{}
	}
	// Routine discovery/probing can affect targets or write local output files,
	// so these tools are not claimed read-only or safe to replay automatically.
	for _, name := range []string{"subfinder_enum", "dns_lookup", "waybackurls", "gau_urls", "httpx_probe", "whatweb_fingerprint", "katana_crawl", "testssl_scan", "arjun_discover", "nmap_port_scan", "nmap_service_detect"} {
		policies[name] = mcp.ToolPolicy{NetworkAccess: true}
	}
	// Raw packet scans may need capabilities even though approval is not required.
	policies["nmap_port_scan"] = mcp.ToolPolicy{NetworkAccess: true, RequiresPrivileges: true}
	policies["barzakh_scan"] = mcp.ToolPolicy{} // Optional report output writes files.
	// Baseband firmware analysis reads images and writes local report files.
	for _, name := range []string{"telecom_firmware_analyze", "telecom_firmware_extract", "telecom_firmware_diff", "telecom_firmware_nv_dump"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true}
	}
	// Small idempotent local config write; never executes anything.
	policies["aegis_defense_config_write"] = mcp.ToolPolicy{RetrySafe: true}
	// Defense-engine HTTP queries touch the network (loopback by default).
	for _, name := range []string{"telecom_threats", "telecom_alerts", "telecom_stats"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, NetworkAccess: true}
	}
	// Privileged eBPF defense daemons: long-running, root-required.
	for _, name := range []string{"aegis_defense_start", "telecom_defense_start"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true}
	}
	// eBPF rootkit and telecom interception loaders: kernel-level offense,
	// destructive-capable, approval-gated. Never auto-approved.
	for _, name := range []string{"aegis_offense_start", "telecom_offense_start"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true, NetworkAccess: true}
	}
	// C2 and scanner servers: long-running listeners, approval-gated. The
	// KubeDagger server binds 0.0.0.0:443 by default.
	policies["kubedagger_server_start"] = mcp.ToolPolicy{NetworkAccess: true, RequiresPrivileges: true}
	policies["barzakh_server_start"] = mcp.ToolPolicy{NetworkAccess: true}
	// Stopping a daemon mutates operator state but is not target-facing.
	for _, name := range []string{"aegis_defense_stop", "telecom_defense_stop", "aegis_offense_stop", "telecom_offense_stop", "kubedagger_server_stop", "barzakh_server_stop"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true, RetrySafe: true}
	}
	// Status queries over managed daemons are read-only.
	for _, name := range []string{"aegis_defense_status", "telecom_defense_status", "aegis_offense_status", "telecom_offense_status", "telecom_correlator_status", "kubedagger_server_status", "barzakh_server_status"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, RequiresPrivileges: true}
	}
	// Daemon stops are replayable operator actions.
	for _, name := range []string{"telecom_correlator_stop"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true, RetrySafe: true}
	}
	// RF transmission (SDR inject/relay/selftest) and baseband firmware
	// patching are high-impact and regulated; approval-gated.
	for _, name := range []string{"telecom_sdr_inject", "telecom_sdr_relay", "telecom_sdr_selftest", "telecom_firmware_patch"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true}
	}
	// The correlator binds a loopback TCP listener.
	policies["telecom_correlator_start"] = mcp.ToolPolicy{NetworkAccess: true}
	// Driving a running rootkit over its C2 channel (hide/unhide/exfil/
	// kill-switch) touches a live target; approval-gated.
	policies["aegis_c2_send"] = mcp.ToolPolicy{NetworkAccess: true, RequiresPrivileges: true}
	// Metasploit: reference listings and module docs are read-only.
	for _, name := range []string{"msf_payload_list", "msf_module_info"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true}
	}
	// Metasploit module execution and operator resource files launch
	// exploits against targets; approval-gated, never auto-approved.
	for _, name := range []string{"msf_module_run", "msf_resource_run"} {
		policies[name] = mcp.ToolPolicy{NetworkAccess: true}
	}
	// Barzakh report generation always writes a report file.
	policies["barzakh_report"] = mcp.ToolPolicy{}
	// Campaign lifecycle tools: status/list/templates are read-only;
	// start/resume execute tool steps; cancel is a replayable stop.
	for _, name := range []string{"campaign_status", "campaign_list", "campaign_templates", "campaign_template_get"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true}
	}
	for _, name := range []string{"campaign_start", "campaign_resume"} {
		policies[name] = mcp.ToolPolicy{NetworkAccess: true}
	}
	policies["campaign_cancel"] = mcp.ToolPolicy{RetrySafe: true}
	return policies
}
