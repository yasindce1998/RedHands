package nmap

import (
	"os"
	"testing"
)

func TestParseBasicScan(t *testing.T) {
	f, err := os.Open("../../testdata/nmap/basic_scan.xml")
	if err != nil {
		t.Fatalf("opening test fixture: %v", err)
	}
	defer f.Close()

	run, err := Parse(f)
	if err != nil {
		t.Fatalf("parsing XML: %v", err)
	}

	if run.Scanner != "nmap" {
		t.Errorf("expected scanner=nmap, got %s", run.Scanner)
	}

	if len(run.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(run.Hosts))
	}

	host := run.Hosts[0]
	if host.Status.State != "up" {
		t.Errorf("expected host state=up, got %s", host.Status.State)
	}

	if len(host.Addresses) != 1 || host.Addresses[0].Addr != "192.168.1.1" {
		t.Errorf("unexpected address: %+v", host.Addresses)
	}

	openPorts := OpenPorts(host)
	if len(openPorts) != 3 {
		t.Errorf("expected 3 open ports, got %d", len(openPorts))
	}

	if openPorts[0].PortID != 22 || openPorts[0].Service.Name != "ssh" {
		t.Errorf("unexpected first port: %+v", openPorts[0])
	}

	if run.RunStats.Finished.Elapsed != 5.12 {
		t.Errorf("expected elapsed=5.12, got %f", run.RunStats.Finished.Elapsed)
	}
}

func TestParseVulnScan(t *testing.T) {
	f, err := os.Open("../../testdata/nmap/vuln_scan.xml")
	if err != nil {
		t.Fatalf("opening test fixture: %v", err)
	}
	defer f.Close()

	run, err := Parse(f)
	if err != nil {
		t.Fatalf("parsing XML: %v", err)
	}

	findings := ExtractFindings(run)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(findings))
	}

	var foundVuln bool
	for _, f := range findings {
		if f.ScriptID == "http-vuln-cve2021-41773" {
			foundVuln = true
			if f.Severity != "high" {
				t.Errorf("expected severity=high, got %s", f.Severity)
			}
			if len(f.CVEs) == 0 {
				t.Errorf("expected CVEs to be extracted")
			}
		}
	}
	if !foundVuln {
		t.Error("expected to find http-vuln-cve2021-41773")
	}
}

func TestSummary(t *testing.T) {
	f, err := os.Open("../../testdata/nmap/basic_scan.xml")
	if err != nil {
		t.Fatalf("opening test fixture: %v", err)
	}
	defer f.Close()

	run, err := Parse(f)
	if err != nil {
		t.Fatalf("parsing XML: %v", err)
	}

	summary := Summary(run)
	if summary == "" {
		t.Error("summary should not be empty")
	}

	if !contains(summary, "192.168.1.1") {
		t.Error("summary should contain host address")
	}
	if !contains(summary, "ssh") {
		t.Error("summary should contain service name")
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
