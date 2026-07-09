package report

type ComplianceControl struct {
	Framework string `json:"framework"`
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
}

type ComplianceMapping struct {
	TechniqueID string              `json:"technique_id"`
	Technique   string              `json:"technique"`
	Controls    []ComplianceControl `json:"controls"`
}

var complianceTable = map[string][]ComplianceControl{
	"T1595": {
		{Framework: "NIST 800-53", ControlID: "RA-5", Title: "Vulnerability Monitoring and Scanning"},
		{Framework: "PCI-DSS", ControlID: "11.2", Title: "Network Vulnerability Scans"},
		{Framework: "ISO 27001", ControlID: "A.12.6.1", Title: "Management of Technical Vulnerabilities"},
	},
	"T1046": {
		{Framework: "NIST 800-53", ControlID: "CM-7", Title: "Least Functionality"},
		{Framework: "PCI-DSS", ControlID: "1.1.6", Title: "Documentation of Services/Ports"},
		{Framework: "ISO 27001", ControlID: "A.13.1.1", Title: "Network Controls"},
	},
	"T1110": {
		{Framework: "NIST 800-53", ControlID: "IA-5", Title: "Authenticator Management"},
		{Framework: "PCI-DSS", ControlID: "8.2.3", Title: "Password Complexity"},
		{Framework: "ISO 27001", ControlID: "A.9.4.3", Title: "Password Management System"},
	},
	"T1003": {
		{Framework: "NIST 800-53", ControlID: "IA-5(1)", Title: "Password-Based Authentication"},
		{Framework: "PCI-DSS", ControlID: "8.2.1", Title: "Unique Identification"},
		{Framework: "ISO 27001", ControlID: "A.9.2.4", Title: "Secret Authentication Information"},
	},
	"T1078": {
		{Framework: "NIST 800-53", ControlID: "AC-2", Title: "Account Management"},
		{Framework: "PCI-DSS", ControlID: "7.1", Title: "Limit Access to System Components"},
		{Framework: "ISO 27001", ControlID: "A.9.2.1", Title: "User Registration and De-registration"},
	},
	"T1021": {
		{Framework: "NIST 800-53", ControlID: "AC-17", Title: "Remote Access"},
		{Framework: "PCI-DSS", ControlID: "8.1.5", Title: "Third-party Remote Access"},
		{Framework: "ISO 27001", ControlID: "A.6.2.2", Title: "Teleworking"},
	},
	"T1059": {
		{Framework: "NIST 800-53", ControlID: "CM-7(2)", Title: "Prevent Program Execution"},
		{Framework: "PCI-DSS", ControlID: "6.5.1", Title: "Injection Flaws"},
		{Framework: "ISO 27001", ControlID: "A.12.5.1", Title: "Installation of Software"},
	},
	"T1190": {
		{Framework: "NIST 800-53", ControlID: "SI-2", Title: "Flaw Remediation"},
		{Framework: "PCI-DSS", ControlID: "6.2", Title: "Security Patches"},
		{Framework: "ISO 27001", ControlID: "A.12.6.1", Title: "Management of Technical Vulnerabilities"},
	},
	"T1071": {
		{Framework: "NIST 800-53", ControlID: "SC-7", Title: "Boundary Protection"},
		{Framework: "PCI-DSS", ControlID: "1.3", Title: "Prohibit Direct Public Access"},
		{Framework: "ISO 27001", ControlID: "A.13.1.3", Title: "Segregation in Networks"},
	},
	"T1557": {
		{Framework: "NIST 800-53", ControlID: "SC-8", Title: "Transmission Confidentiality and Integrity"},
		{Framework: "PCI-DSS", ControlID: "4.1", Title: "Strong Cryptography for Transmission"},
		{Framework: "ISO 27001", ControlID: "A.13.2.1", Title: "Information Transfer Policies"},
	},
	"T1566": {
		{Framework: "NIST 800-53", ControlID: "AT-2", Title: "Literacy Training and Awareness"},
		{Framework: "PCI-DSS", ControlID: "12.6", Title: "Security Awareness Program"},
		{Framework: "ISO 27001", ControlID: "A.7.2.2", Title: "Information Security Awareness"},
	},
	"T1548": {
		{Framework: "NIST 800-53", ControlID: "AC-6", Title: "Least Privilege"},
		{Framework: "PCI-DSS", ControlID: "7.1.2", Title: "Restrict Access Based on Need"},
		{Framework: "ISO 27001", ControlID: "A.9.1.2", Title: "Access to Networks and Network Services"},
	},
	"T1098": {
		{Framework: "NIST 800-53", ControlID: "AC-2(4)", Title: "Automated Audit Actions"},
		{Framework: "PCI-DSS", ControlID: "10.2.5", Title: "Changes to Identification and Authentication"},
		{Framework: "ISO 27001", ControlID: "A.9.2.5", Title: "Review of User Access Rights"},
	},
	"T1558": {
		{Framework: "NIST 800-53", ControlID: "IA-2(8)", Title: "Network Access to Privileged Accounts"},
		{Framework: "PCI-DSS", ControlID: "8.5", Title: "MFA for Administrative Access"},
		{Framework: "ISO 27001", ControlID: "A.9.4.2", Title: "Secure Log-on Procedures"},
	},
	"T1087": {
		{Framework: "NIST 800-53", ControlID: "AC-2", Title: "Account Management"},
		{Framework: "PCI-DSS", ControlID: "8.1.1", Title: "Assign Unique ID"},
		{Framework: "ISO 27001", ControlID: "A.9.2.1", Title: "User Registration and De-registration"},
	},
}

func LookupCompliance(techniqueID string) []ComplianceControl {
	return complianceTable[techniqueID]
}

func MapFindingsToCompliance(findings []struct {
	TechniqueID string
	Technique   string
}) []ComplianceMapping {
	var mappings []ComplianceMapping

	seen := make(map[string]bool)
	for _, f := range findings {
		if seen[f.TechniqueID] {
			continue
		}
		seen[f.TechniqueID] = true

		controls := LookupCompliance(f.TechniqueID)
		if len(controls) == 0 {
			continue
		}

		mappings = append(mappings, ComplianceMapping{
			TechniqueID: f.TechniqueID,
			Technique:   f.Technique,
			Controls:    controls,
		})
	}

	return mappings
}

func AllFrameworks() []string {
	return []string{"NIST 800-53", "PCI-DSS", "ISO 27001"}
}

func ControlsByFramework(framework string) []ComplianceControl {
	seen := make(map[string]bool)
	var controls []ComplianceControl

	for _, ctrls := range complianceTable {
		for _, c := range ctrls {
			if c.Framework == framework && !seen[c.ControlID] {
				seen[c.ControlID] = true
				controls = append(controls, c)
			}
		}
	}

	return controls
}
