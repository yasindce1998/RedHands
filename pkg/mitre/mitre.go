package mitre

// Technique represents a MITRE ATT&CK technique.
type Technique struct {
	ID          string
	Name        string
	Tactic      string
	Description string
}

// ToolMapping maps tool names to their associated MITRE ATT&CK techniques.
var ToolMapping = map[string][]string{
	// Reconnaissance
	"amass_enum":        {"T1590", "T1596"},
	"subfinder_enum":    {"T1590.002"},
	"dns_lookup":        {"T1590.002"},
	"gau_urls":          {"T1593"},
	"wayback_urls":      {"T1593"},
	"arjun_params":      {"T1595.002"},

	// Scanning
	"nmap_scan":         {"T1046"},
	"masscan_scan":      {"T1046"},
	"nuclei_scan":       {"T1595.002"},

	// Credential Access
	"hydra_brute":          {"T1110.001"},
	"hashcat_crack":        {"T1110.002"},
	"john_crack":           {"T1110.002"},
	"responder_start":      {"T1557.001"},
	"bloodhound_collect":   {"T1087.002"},

	// Active Directory
	"bloodhound_find_path":    {"T1069.002"},
	"bloodhound_analyze":      {"T1087.002"},
	"coercion_petitpotam":     {"T1187"},
	"coercion_printerbug":     {"T1187"},
	"coercion_dfscoerce":      {"T1187"},
	"evilwinrm_shell":         {"T1021.006"},
	"evilwinrm_upload":        {"T1105"},
	"evilwinrm_download":      {"T1005"},
	"evilwinrm_dll_inject":    {"T1055.001"},
	"evilwinrm_ps_exec":       {"T1059.001"},

	// Exploitation
	"metasploit_exploit":  {"T1203"},
	"sqlmap_scan":         {"T1190"},
	"searchsploit":        {"T1588.005"},
	"crackmapexec_exec":   {"T1021.002"},

	// Lateral Movement
	"crackmapexec_smb":    {"T1021.002"},
	"chisel_tunnel":       {"T1572"},
	"ligolo_tunnel":       {"T1572"},
	"socat_tunnel":        {"T1572"},

	// Privilege Escalation
	"linpeas_scan":        {"T1068"},

	// Command & Control
	"sliver_generate":     {"T1071.001"},
	"sliver_listener":     {"T1571"},

	// Wireless
	"wireless_monitor":    {"T1040"},
	"wireless_scan":       {"T1040"},
	"wireless_deauth":     {"T1498.001"},
	"wireless_capture":    {"T1040"},
	"wireless_crack":      {"T1110.002"},

	// Cloud
	"cloud_scout_aws":       {"T1580"},
	"cloud_scout_azure":     {"T1580"},
	"cloud_prowler":         {"T1580"},
	"cloud_pacu_enum":       {"T1087.004"},
	"cloud_roadtools_auth":  {"T1078.004"},
	"cloud_roadtools_dump":  {"T1087.004"},
	"cloud_enum_s3":         {"T1530"},
	"cloud_enum_blobs":      {"T1530"},

	// Mobile
	"mobile_frida_attach":     {"T1404"},
	"mobile_frida_spawn":      {"T1404"},
	"mobile_objection":        {"T1404"},
	"mobile_apk_decompile":    {"T1424"},
	"mobile_adb_shell":        {"T1421"},

	// Phishing
	"phishing_campaign_create": {"T1566.001"},
	"phishing_template_create": {"T1566.001"},

	// Web
	"nikto_scan":          {"T1595.002"},
	"gobuster_dir":        {"T1595.003"},
	"ffuf_fuzz":           {"T1595.003"},
	"xsstrike_scan":       {"T1189"},
	"wpscan_scan":         {"T1595.002"},

	// Fuzzing
	"ffuf_fuzz_dir":       {"T1595.003"},
}

// Techniques is the full technique catalog.
var Techniques = map[string]*Technique{
	"T1046":     {ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"},
	"T1040":     {ID: "T1040", Name: "Network Sniffing", Tactic: "Credential Access"},
	"T1055.001": {ID: "T1055.001", Name: "DLL Injection", Tactic: "Privilege Escalation"},
	"T1059.001": {ID: "T1059.001", Name: "PowerShell", Tactic: "Execution"},
	"T1068":     {ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "Privilege Escalation"},
	"T1071.001": {ID: "T1071.001", Name: "Web Protocols", Tactic: "Command and Control"},
	"T1078.004": {ID: "T1078.004", Name: "Cloud Accounts", Tactic: "Initial Access"},
	"T1087.002": {ID: "T1087.002", Name: "Domain Account Discovery", Tactic: "Discovery"},
	"T1087.004": {ID: "T1087.004", Name: "Cloud Account Discovery", Tactic: "Discovery"},
	"T1105":     {ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "Command and Control"},
	"T1110.001": {ID: "T1110.001", Name: "Password Guessing", Tactic: "Credential Access"},
	"T1110.002": {ID: "T1110.002", Name: "Password Cracking", Tactic: "Credential Access"},
	"T1187":     {ID: "T1187", Name: "Forced Authentication", Tactic: "Credential Access"},
	"T1189":     {ID: "T1189", Name: "Drive-by Compromise", Tactic: "Initial Access"},
	"T1190":     {ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"},
	"T1203":     {ID: "T1203", Name: "Exploitation for Client Execution", Tactic: "Execution"},
	"T1005":     {ID: "T1005", Name: "Data from Local System", Tactic: "Collection"},
	"T1021.002": {ID: "T1021.002", Name: "SMB/Windows Admin Shares", Tactic: "Lateral Movement"},
	"T1021.006": {ID: "T1021.006", Name: "Windows Remote Management", Tactic: "Lateral Movement"},
	"T1069.002": {ID: "T1069.002", Name: "Domain Groups", Tactic: "Discovery"},
	"T1404":     {ID: "T1404", Name: "Exploitation for Privilege Escalation (Mobile)", Tactic: "Privilege Escalation"},
	"T1421":     {ID: "T1421", Name: "System Network Connections Discovery (Mobile)", Tactic: "Discovery"},
	"T1424":     {ID: "T1424", Name: "Process Discovery (Mobile)", Tactic: "Discovery"},
	"T1498.001": {ID: "T1498.001", Name: "Direct Network Flood", Tactic: "Impact"},
	"T1530":     {ID: "T1530", Name: "Data from Cloud Storage", Tactic: "Collection"},
	"T1557.001": {ID: "T1557.001", Name: "LLMNR/NBT-NS Poisoning", Tactic: "Credential Access"},
	"T1566.001": {ID: "T1566.001", Name: "Spearphishing Attachment", Tactic: "Initial Access"},
	"T1571":     {ID: "T1571", Name: "Non-Standard Port", Tactic: "Command and Control"},
	"T1572":     {ID: "T1572", Name: "Protocol Tunneling", Tactic: "Command and Control"},
	"T1580":     {ID: "T1580", Name: "Cloud Infrastructure Discovery", Tactic: "Discovery"},
	"T1588.005": {ID: "T1588.005", Name: "Exploits", Tactic: "Resource Development"},
	"T1590":     {ID: "T1590", Name: "Gather Victim Network Information", Tactic: "Reconnaissance"},
	"T1590.002": {ID: "T1590.002", Name: "DNS", Tactic: "Reconnaissance"},
	"T1593":     {ID: "T1593", Name: "Search Open Websites/Domains", Tactic: "Reconnaissance"},
	"T1595.002": {ID: "T1595.002", Name: "Vulnerability Scanning", Tactic: "Reconnaissance"},
	"T1595.003": {ID: "T1595.003", Name: "Wordlist Scanning", Tactic: "Reconnaissance"},
	"T1596":     {ID: "T1596", Name: "Search Open Technical Databases", Tactic: "Reconnaissance"},
}

// Lookup returns techniques associated with a tool.
func Lookup(toolName string) []*Technique {
	ids, ok := ToolMapping[toolName]
	if !ok {
		return nil
	}

	var result []*Technique
	for _, id := range ids {
		if t, ok := Techniques[id]; ok {
			result = append(result, t)
		}
	}
	return result
}

// LookupIDs returns technique IDs associated with a tool.
func LookupIDs(toolName string) []string {
	return ToolMapping[toolName]
}

// GetTechnique returns a technique by ID.
func GetTechnique(id string) (*Technique, bool) {
	t, ok := Techniques[id]
	return t, ok
}

// TacticTechniques returns all techniques for a given tactic.
func TacticTechniques(tactic string) []*Technique {
	var result []*Technique
	for _, t := range Techniques {
		if t.Tactic == tactic {
			result = append(result, t)
		}
	}
	return result
}
