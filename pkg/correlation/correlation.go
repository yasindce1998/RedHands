package correlation

import (
	"fmt"
	"sort"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

// Insight represents a correlated finding derived from multiple data points.
type Insight struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Hosts       []string `json:"hosts"`
	Findings    []string `json:"findings"`
	Suggestion  string   `json:"suggestion"`
}

// Engine performs correlation analysis across target database findings.
type Engine struct {
	store *targetdb.Store
}

// NewEngine creates a correlation engine backed by the given store.
func NewEngine(store *targetdb.Store) *Engine {
	return &Engine{store: store}
}

// Analyze runs all correlation rules and returns insights.
func (e *Engine) Analyze() []Insight {
	var insights []Insight

	insights = append(insights, e.escalationChains()...)
	insights = append(insights, e.lateralMovement()...)
	insights = append(insights, e.highRiskServices()...)
	insights = append(insights, e.credentialReuse()...)

	sort.Slice(insights, func(i, j int) bool {
		return severityRank(insights[i].Severity) > severityRank(insights[j].Severity)
	})

	return insights
}

// escalationChains detects hosts with multiple vulnerabilities suggesting privilege escalation.
func (e *Engine) escalationChains() []Insight {
	var insights []Insight

	hosts := e.store.ListHosts()
	for _, host := range hosts {
		findings := e.store.QueryFindings(host.IP, "", "")
		if len(findings) < 2 {
			continue
		}

		var critHigh []*targetdb.Finding
		for _, f := range findings {
			if f.Severity == "critical" || f.Severity == "high" {
				critHigh = append(critHigh, f)
			}
		}

		if len(critHigh) >= 2 {
			var findingIDs []string
			var titles []string
			for _, f := range critHigh {
				findingIDs = append(findingIDs, f.ID)
				titles = append(titles, f.Title)
			}

			insights = append(insights, Insight{
				Type:        "escalation_chain",
				Severity:    "critical",
				Title:       fmt.Sprintf("Potential escalation chain on %s", host.IP),
				Description: fmt.Sprintf("Multiple high/critical findings on same host suggest privilege escalation path: %v", titles),
				Hosts:       []string{host.IP},
				Findings:    findingIDs,
				Suggestion:  "Investigate combining these vulnerabilities for full system compromise",
			})
		}
	}

	return insights
}

// lateralMovement detects credential+service combinations enabling lateral movement.
func (e *Engine) lateralMovement() []Insight {
	var insights []Insight

	creds := e.store.ListCredentials()
	if len(creds) == 0 {
		return nil
	}

	hosts := e.store.ListHosts()
	services := e.store.ListServices("")

	// Build service map: host -> services
	hostServices := make(map[string][]*targetdb.Service)
	for _, svc := range services {
		hostServices[svc.Host] = append(hostServices[svc.Host], svc)
	}

	// For each credential, check which hosts it can reach
	for _, cred := range creds {
		if !cred.Valid {
			continue
		}

		var reachable []string
		for _, host := range hosts {
			if host.IP == cred.Host {
				continue
			}
			for _, svc := range hostServices[host.IP] {
				if canAuth(cred, svc) {
					reachable = append(reachable, host.IP)
					break
				}
			}
		}

		if len(reachable) > 0 {
			insights = append(insights, Insight{
				Type:        "lateral_movement",
				Severity:    "high",
				Title:       fmt.Sprintf("Lateral movement possible with %s\\%s", cred.Domain, cred.Username),
				Description: fmt.Sprintf("Valid credential can authenticate to %d additional hosts", len(reachable)),
				Hosts:       reachable,
				Findings:    nil,
				Suggestion:  fmt.Sprintf("Use credential %s to pivot to: %v", cred.Username, reachable),
			})
		}
	}

	return insights
}

// highRiskServices identifies exposed high-risk services.
func (e *Engine) highRiskServices() []Insight {
	var insights []Insight

	services := e.store.ListServices("")
	riskPorts := map[int]string{
		445:  "SMB",
		3389: "RDP",
		22:   "SSH",
		1433: "MSSQL",
		3306: "MySQL",
		5432: "PostgreSQL",
		6379: "Redis",
		27017: "MongoDB",
		9200: "Elasticsearch",
		2049: "NFS",
	}

	hostRisk := make(map[string][]string)
	for _, svc := range services {
		if name, risky := riskPorts[svc.Port]; risky {
			hostRisk[svc.Host] = append(hostRisk[svc.Host], fmt.Sprintf("%s:%d", name, svc.Port))
		}
	}

	for host, svcs := range hostRisk {
		if len(svcs) >= 3 {
			insights = append(insights, Insight{
				Type:        "high_risk_exposure",
				Severity:    "high",
				Title:       fmt.Sprintf("Multiple high-risk services on %s", host),
				Description: fmt.Sprintf("Host exposes %d sensitive services: %v", len(svcs), svcs),
				Hosts:       []string{host},
				Suggestion:  "Prioritize this host for exploitation - large attack surface",
			})
		}
	}

	return insights
}

// credentialReuse detects credentials used across multiple hosts.
func (e *Engine) credentialReuse() []Insight {
	var insights []Insight

	creds := e.store.ListCredentials()

	// Group by username+domain
	type credKey struct{ user, domain string }
	groups := make(map[credKey][]string)
	for _, c := range creds {
		k := credKey{c.Username, c.Domain}
		groups[k] = append(groups[k], c.Host)
	}

	for k, hosts := range groups {
		if len(hosts) < 2 {
			continue
		}
		insights = append(insights, Insight{
			Type:        "credential_reuse",
			Severity:    "medium",
			Title:       fmt.Sprintf("Credential reuse: %s\\%s across %d hosts", k.domain, k.user, len(hosts)),
			Description: "Same credential found on multiple hosts suggesting password reuse",
			Hosts:       hosts,
			Suggestion:  "Test this credential against all hosts with authentication services",
		})
	}

	return insights
}

func canAuth(cred *targetdb.Credential, svc *targetdb.Service) bool {
	authPorts := map[int]bool{
		445: true, 3389: true, 22: true, 5985: true, 5986: true,
		1433: true, 3306: true, 5432: true, 389: true, 636: true,
	}
	return authPorts[svc.Port]
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
