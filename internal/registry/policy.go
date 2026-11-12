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
	// Stopping a daemon mutates operator state but is not target-facing.
	for _, name := range []string{"aegis_defense_stop", "telecom_defense_stop"} {
		policies[name] = mcp.ToolPolicy{RequiresPrivileges: true, RetrySafe: true}
	}
	// Status queries over managed daemons are read-only.
	for _, name := range []string{"aegis_defense_status", "telecom_defense_status"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true, RequiresPrivileges: true}
	}
	return policies
}
