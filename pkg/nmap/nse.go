package nmap

import (
	"regexp"
	"strings"
)

var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func ExtractFindings(run *NmapRun) []Finding {
	var findings []Finding

	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			for _, script := range port.Scripts {
				f := scriptToFinding(script, port.PortID, port.Protocol)
				if f != nil {
					findings = append(findings, *f)
				}
			}
		}
		for _, script := range host.Scripts {
			f := scriptToFinding(script, 0, "")
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings
}

func scriptToFinding(script Script, port int, protocol string) *Finding {
	if script.Output == "" {
		return nil
	}

	finding := &Finding{
		ScriptID:    script.ID,
		Port:        port,
		Protocol:    protocol,
		Title:       script.ID,
		Description: script.Output,
		CVEs:        cvePattern.FindAllString(script.Output, -1),
	}

	finding.Severity = inferSeverity(script)

	for _, elem := range script.Elements {
		switch strings.ToLower(elem.Key) {
		case "title":
			finding.Title = elem.Value
		case "state":
			if strings.Contains(strings.ToLower(elem.Value), "vulnerable") {
				if finding.Severity == "info" {
					finding.Severity = "high"
				}
			}
		}
	}

	return finding
}

func inferSeverity(script Script) string {
	output := strings.ToLower(script.Output)
	switch {
	case strings.Contains(output, "vulnerable"):
		return "high"
	case strings.Contains(output, "potentially vulnerable"):
		return "medium"
	case strings.Contains(output, "not vulnerable"):
		return "info"
	default:
		return "info"
	}
}
