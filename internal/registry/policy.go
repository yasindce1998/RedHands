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
	return policies
}
