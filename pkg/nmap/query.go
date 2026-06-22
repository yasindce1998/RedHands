package nmap

import (
	"fmt"
	"strings"
)

func OpenPorts(host Host) []Port {
	var open []Port
	for _, p := range host.Ports {
		if p.State.State == "open" {
			open = append(open, p)
		}
	}
	return open
}

func Services(host Host) []Service {
	var svcs []Service
	for _, p := range host.Ports {
		if p.State.State == "open" && p.Service.Name != "" {
			svcs = append(svcs, p.Service)
		}
	}
	return svcs
}

func Vulnerabilities(run *NmapRun) []Finding {
	return ExtractFindings(run)
}

func Summary(run *NmapRun) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Nmap scan completed: %d host(s) scanned\n", len(run.Hosts))

	for _, host := range run.Hosts {
		addr := hostAddress(host)
		fmt.Fprintf(&sb, "\n## Host: %s (status: %s)\n", addr, host.Status.State)

		openPorts := OpenPorts(host)
		if len(openPorts) == 0 {
			sb.WriteString("No open ports found.\n")
			continue
		}

		fmt.Fprintf(&sb, "Open ports: %d\n\n", len(openPorts))
		sb.WriteString("| Port | Protocol | Service | Version |\n")
		sb.WriteString("|------|----------|---------|----------|\n")

		for _, p := range openPorts {
			version := p.Service.Product
			if p.Service.Version != "" {
				version += " " + p.Service.Version
			}
			fmt.Fprintf(&sb, "| %d | %s | %s | %s |\n",
				p.PortID, p.Protocol, p.Service.Name, strings.TrimSpace(version))
		}

		if len(host.OS.Matches) > 0 {
			fmt.Fprintf(&sb, "\nOS Detection: %s (accuracy: %d%%)\n",
				host.OS.Matches[0].Name, host.OS.Matches[0].Accuracy)
		}

		findings := ExtractFindings(&NmapRun{Hosts: []Host{host}})
		if len(findings) > 0 {
			fmt.Fprintf(&sb, "\nVulnerabilities/Scripts: %d findings\n", len(findings))
			for _, f := range findings {
				fmt.Fprintf(&sb, "- [%s] %s (port %d/%s)\n", f.Severity, f.Title, f.Port, f.Protocol)
				if len(f.CVEs) > 0 {
					fmt.Fprintf(&sb, "  CVEs: %s\n", strings.Join(f.CVEs, ", "))
				}
			}
		}
	}

	if run.RunStats.Finished.Elapsed > 0 {
		fmt.Fprintf(&sb, "\nScan duration: %.2f seconds\n", run.RunStats.Finished.Elapsed)
	}

	return sb.String()
}

func hostAddress(host Host) string {
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	if len(host.Addresses) > 0 {
		return host.Addresses[0].Addr
	}
	return "unknown"
}
