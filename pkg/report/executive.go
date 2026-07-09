package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type ExecutiveSummary struct {
	Title          string         `json:"title"`
	GeneratedAt    time.Time      `json:"generated_at"`
	TotalFindings  int            `json:"total_findings"`
	TotalHosts     int            `json:"total_hosts"`
	BySeverity     map[string]int `json:"by_severity"`
	TopRisks       []RiskItem     `json:"top_risks"`
	AffectedHosts  []HostSummary  `json:"affected_hosts"`
	Recommendations []string      `json:"recommendations"`
}

type RiskItem struct {
	Title     string  `json:"title"`
	Host      string  `json:"host"`
	Severity  string  `json:"severity"`
	RiskScore float64 `json:"risk_score"`
}

type HostSummary struct {
	Host         string `json:"host"`
	FindingCount int    `json:"finding_count"`
	MaxSeverity  string `json:"max_severity"`
}

func GenerateExecutiveSummary(findings []*targetdb.Finding, hosts []*targetdb.Host, title string) *ExecutiveSummary {
	if title == "" {
		title = "Executive Summary - Security Assessment"
	}

	summary := &ExecutiveSummary{
		Title:       title,
		GeneratedAt: time.Now(),
		TotalHosts:  len(hosts),
		BySeverity:  make(map[string]int),
	}

	hostFindings := make(map[string]int)
	hostMaxSev := make(map[string]string)

	for _, f := range findings {
		summary.TotalFindings++
		summary.BySeverity[f.Severity]++
		hostFindings[f.Host]++

		if sevRank(f.Severity) > sevRank(hostMaxSev[f.Host]) {
			hostMaxSev[f.Host] = f.Severity
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	topN := 10
	if len(findings) < topN {
		topN = len(findings)
	}
	for _, f := range findings[:topN] {
		summary.TopRisks = append(summary.TopRisks, RiskItem{
			Title:     f.Title,
			Host:      f.Host,
			Severity:  f.Severity,
			RiskScore: f.RiskScore,
		})
	}

	for host, count := range hostFindings {
		summary.AffectedHosts = append(summary.AffectedHosts, HostSummary{
			Host:         host,
			FindingCount: count,
			MaxSeverity:  hostMaxSev[host],
		})
	}
	sort.Slice(summary.AffectedHosts, func(i, j int) bool {
		return summary.AffectedHosts[i].FindingCount > summary.AffectedHosts[j].FindingCount
	})

	summary.Recommendations = generateRecommendations(summary)

	return summary
}

func (s *ExecutiveSummary) RenderMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# ")
	sb.WriteString(s.Title)
	sb.WriteString("\n\n")
	fmt.Fprintf(&sb, "**Date**: %s\n\n", s.GeneratedAt.Format("2006-01-02"))
	sb.WriteString("## Overview\n\n")
	fmt.Fprintf(&sb, "| Metric | Value |\n|--------|-------|\n")
	fmt.Fprintf(&sb, "| Total Findings | %d |\n", s.TotalFindings)
	fmt.Fprintf(&sb, "| Hosts Assessed | %d |\n", s.TotalHosts)
	fmt.Fprintf(&sb, "| Critical | %d |\n", s.BySeverity["critical"])
	fmt.Fprintf(&sb, "| High | %d |\n", s.BySeverity["high"])
	fmt.Fprintf(&sb, "| Medium | %d |\n", s.BySeverity["medium"])
	fmt.Fprintf(&sb, "| Low | %d |\n", s.BySeverity["low"])
	fmt.Fprintf(&sb, "| Info | %d |\n\n", s.BySeverity["info"])

	if len(s.TopRisks) > 0 {
		sb.WriteString("## Top Risks\n\n")
		sb.WriteString("| # | Finding | Host | Severity | Score |\n")
		sb.WriteString("|---|---------|------|----------|-------|\n")
		for i, r := range s.TopRisks {
			fmt.Fprintf(&sb, "| %d | %s | %s | %s | %.1f |\n", i+1, r.Title, r.Host, r.Severity, r.RiskScore)
		}
		sb.WriteString("\n")
	}

	if len(s.Recommendations) > 0 {
		sb.WriteString("## Recommendations\n\n")
		for i, r := range s.Recommendations {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, r)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func generateRecommendations(s *ExecutiveSummary) []string {
	var recs []string

	if s.BySeverity["critical"] > 0 {
		recs = append(recs, fmt.Sprintf("Immediately address %d critical findings that pose imminent risk to the environment", s.BySeverity["critical"]))
	}
	if s.BySeverity["high"] > 0 {
		recs = append(recs, fmt.Sprintf("Remediate %d high-severity findings within 30 days", s.BySeverity["high"]))
	}
	if s.BySeverity["medium"] > 0 {
		recs = append(recs, fmt.Sprintf("Schedule remediation of %d medium-severity findings within 90 days", s.BySeverity["medium"]))
	}
	if len(s.AffectedHosts) > 3 {
		recs = append(recs, "Conduct network segmentation review given the number of affected hosts")
	}

	return recs
}

func sevRank(sev string) int {
	switch sev {
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
