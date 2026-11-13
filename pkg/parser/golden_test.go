package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Golden tests against the fixture corpus in testdata/nuclei/ and
// testdata/masscan/. The fixtures are schema-derived (nuclei and masscan are
// not installed locally and need live targets/raw sockets; see the READMEs
// there) but carry the full field set the real tools emit, including keys
// the parsers must skip. These tests pin the parse mapping from the real
// JSONL/JSON output shapes to the normalized structures.

func loadParserFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return data
}

func TestNucleiJSONGolden_ParsesRealFieldNames(t *testing.T) {
	data := loadParserFixture(t, "nuclei", "findings.jsonl")

	raw, err := (&NucleiJSONParser{}).Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var result struct {
		TotalFindings int `json:"total_findings"`
		Findings      []struct {
			TemplateID       string   `json:"template_id"`
			Name             string   `json:"name"`
			Severity         string   `json:"severity"`
			Host             string   `json:"host"`
			MatchedAt        string   `json:"matched_at"`
			Type             string   `json:"type"`
			IP               string   `json:"ip"`
			ExtractedResults []string `json:"extracted_results"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("normalized result is not JSON: %v", err)
	}
	if result.TotalFindings != 5 || len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings from the fixture, got %d (%d in array)", result.TotalFindings, len(result.Findings))
	}

	byTemplate := map[string]struct {
		TemplateID       string   `json:"template_id"`
		Name             string   `json:"name"`
		Severity         string   `json:"severity"`
		Host             string   `json:"host"`
		MatchedAt        string   `json:"matched_at"`
		Type             string   `json:"type"`
		IP               string   `json:"ip"`
		ExtractedResults []string `json:"extracted_results"`
	}{}
	for _, f := range result.Findings {
		byTemplate[f.TemplateID] = f
	}

	// The nuclei JSONL keys are kebab-case ("template-id", "matched-at");
	// the parser must map them to the normalized snake_case output.
	log4j := byTemplate["CVE-2021-44228"]
	if log4j.Severity != "critical" || log4j.Host != "http://192.0.2.50:8080" {
		t.Errorf("log4j finding mapped wrong: %+v", log4j)
	}
	if log4j.Name != "Apache Log4j Remote Code Execution" {
		t.Errorf("info.name not mapped: %+v", log4j)
	}
	if log4j.MatchedAt != "http://192.0.2.50:8080/" {
		t.Errorf("matched-at not mapped: %+v", log4j)
	}
	if log4j.IP != "192.0.2.50" {
		t.Errorf("ip not mapped: %+v", log4j)
	}
	if log4j.Type != "http" {
		t.Errorf("type not mapped: %+v", log4j)
	}

	// extracted-results must survive the mapping.
	nginx := byTemplate["nginx-version"]
	if len(nginx.ExtractedResults) != 1 || nginx.ExtractedResults[0] != "1.18.0" {
		t.Errorf("extracted-results not mapped: %+v", nginx)
	}

	// dns- and file-type findings carry no ip; the field must be absent, not
	// fatal.
	dns := byTemplate["dns-takeover-detect"]
	if dns.Type != "dns" || dns.IP != "" {
		t.Errorf("dns finding mapped wrong: %+v", dns)
	}
	file := byTemplate["CVE-2019-5418"]
	if file.Type != "file" || file.Host != "/opt/target/app/Gemfile.lock" {
		t.Errorf("file finding mapped wrong: %+v", file)
	}
}

func TestNucleiJSONGolden_SkipsMalformedLines(t *testing.T) {
	data := append(loadParserFixture(t, "nuclei", "findings.jsonl"), []byte("\nthis is not json\n")...)
	raw, err := (&NucleiJSONParser{}).Parse(data)
	if err != nil {
		t.Fatalf("parse with malformed line: %v", err)
	}
	var result struct {
		TotalFindings int `json:"total_findings"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("normalized result is not JSON: %v", err)
	}
	if result.TotalFindings != 5 {
		t.Errorf("malformed line must be skipped, got %d findings", result.TotalFindings)
	}
}

func TestMasscanJSONGolden_MergesHostsFromRawEntries(t *testing.T) {
	data := loadParserFixture(t, "masscan", "hosts.json")

	raw, err := (&MasscanJSONParser{}).Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var result struct {
		TotalHosts int `json:"total_hosts"`
		Hosts      []struct {
			Address string `json:"address"`
			Ports   []struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				State    string `json:"state"`
				TTL      int    `json:"ttl"`
			} `json:"ports"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("normalized result is not JSON: %v", err)
	}

	// 4 raw entries but only 3 distinct IPs: the parser must merge the two
	// 192.0.2.50 entries into one host.
	if result.TotalHosts != 3 || len(result.Hosts) != 3 {
		t.Fatalf("expected 3 merged hosts, got %d (%d in array)", result.TotalHosts, len(result.Hosts))
	}

	byAddress := map[string]struct {
		Address string `json:"address"`
		Ports   []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			State    string `json:"state"`
			TTL      int    `json:"ttl"`
		} `json:"ports"`
	}{}
	for _, h := range result.Hosts {
		byAddress[h.Address] = h
	}

	// masscan's raw "status" field must surface as the normalized "state",
	// and merged duplicate entries accumulate their ports.
	host := byAddress["192.0.2.50"]
	if len(host.Ports) != 4 {
		t.Errorf("expected 4 merged ports for 192.0.2.50 (22, 8080, 8443, 8080-dup), got %d", len(host.Ports))
	}
	seen := map[int]bool{}
	for _, p := range host.Ports {
		seen[p.Port] = true
		if p.Protocol != "tcp" || p.State != "open" {
			t.Errorf("port %d mapped wrong: %+v", p.Port, p)
		}
	}
	for _, want := range []int{22, 8080, 8443} {
		if !seen[want] {
			t.Errorf("port %d missing from merged host", want)
		}
	}

	// Mixed protocols map with their own proto value.
	other := byAddress["198.51.100.24"]
	udpSeen := false
	for _, p := range other.Ports {
		if p.Port == 53 && p.Protocol == "udp" && p.State == "open" {
			udpSeen = true
		}
	}
	if !udpSeen {
		t.Errorf("udp/53 not mapped for 198.51.100.24: %+v", other.Ports)
	}
}

func TestMasscanJSONGolden_RejectsNonArray(t *testing.T) {
	if _, err := (&MasscanJSONParser{}).Parse([]byte(`{"ip": "192.0.2.1"}`)); err == nil {
		t.Error("masscan JSON output is a top-level array; an object must be a parse error")
	}
}
