package parser

import (
	"encoding/json"
	"testing"
)

func TestRegistryLookupByName(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		name   string
		lookup string
		wantOK bool
	}{
		{"nmap_xml exists", "nmap_xml", true},
		{"nuclei_json exists", "nuclei_json", true},
		{"masscan_json exists", "masscan_json", true},
		{"unknown returns false", "unknown_parser", false},
		{"empty string returns false", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := reg.Get(tt.lookup)
			if ok != tt.wantOK {
				t.Errorf("Get(%q) ok = %v, want %v", tt.lookup, ok, tt.wantOK)
			}
			if ok && p.Name() != tt.lookup {
				t.Errorf("parser.Name() = %q, want %q", p.Name(), tt.lookup)
			}
			if !ok && p != nil {
				t.Errorf("expected nil parser for missing name %q", tt.lookup)
			}
		})
	}
}

func TestRegistryListContainsAllParsers(t *testing.T) {
	reg := NewRegistry()
	list := reg.List()

	if len(list) != 3 {
		t.Fatalf("expected 3 parsers in registry, got %d", len(list))
	}

	expected := map[string]bool{
		"nmap_xml":     false,
		"nuclei_json":  false,
		"masscan_json": false,
	}
	for _, name := range list {
		if _, ok := expected[name]; !ok {
			t.Errorf("unexpected parser in list: %q", name)
		}
		expected[name] = true
	}
	for name, found := range expected {
		if !found {
			t.Errorf("missing parser in list: %q", name)
		}
	}
}

func TestNmapXMLParser(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		checkFunc func(t *testing.T, raw json.RawMessage)
	}{
		{
			name: "valid scan with two hosts",
			input: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.0/24" startstr="Mon Jan 1 00:00:00 2024">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="gateway.local"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nmapResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.Scanner != "nmap" {
					t.Errorf("scanner = %q, want %q", parsed.Scanner, "nmap")
				}
				if parsed.Args != "nmap -sV 192.168.1.0/24" {
					t.Errorf("args = %q, want %q", parsed.Args, "nmap -sV 192.168.1.0/24")
				}
				if len(parsed.Hosts) != 2 {
					t.Fatalf("expected 2 hosts, got %d", len(parsed.Hosts))
				}
				h := parsed.Hosts[0]
				if h.Address != "192.168.1.1" {
					t.Errorf("host[0].address = %q, want %q", h.Address, "192.168.1.1")
				}
				if h.Hostname != "gateway.local" {
					t.Errorf("host[0].hostname = %q, want %q", h.Hostname, "gateway.local")
				}
				if len(h.Ports) != 2 {
					t.Fatalf("host[0] expected 2 ports, got %d", len(h.Ports))
				}
				if h.Ports[0].Port != 80 || h.Ports[0].Protocol != "tcp" || h.Ports[0].State != "open" {
					t.Errorf("host[0].ports[0] = %+v, want port=80 proto=tcp state=open", h.Ports[0])
				}
				if h.Ports[0].Service != "http" || h.Ports[0].Product != "nginx" || h.Ports[0].Version != "1.18" {
					t.Errorf("host[0].ports[0] service info = %+v", h.Ports[0])
				}
			},
		},
		{
			name: "host with OS detection",
			input: []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -O 10.0.0.1" startstr="Tue Feb 1 12:00:00 2024">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
      <osmatch name="Linux 5.10" accuracy="90"/>
    </os>
  </host>
</nmaprun>`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nmapResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if len(parsed.Hosts) != 1 {
					t.Fatalf("expected 1 host, got %d", len(parsed.Hosts))
				}
				if len(parsed.Hosts[0].OS) != 2 {
					t.Fatalf("expected 2 OS matches, got %d", len(parsed.Hosts[0].OS))
				}
				if parsed.Hosts[0].OS[0].Name != "Linux 5.4" {
					t.Errorf("os[0].name = %q, want %q", parsed.Hosts[0].OS[0].Name, "Linux 5.4")
				}
				if parsed.Hosts[0].OS[0].Accuracy != 95 {
					t.Errorf("os[0].accuracy = %d, want 95", parsed.Hosts[0].OS[0].Accuracy)
				}
			},
		},
		{
			name: "empty host list",
			input: []byte(`<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap 10.0.0.1" startstr="Wed Mar 1 00:00:00 2024">
</nmaprun>`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nmapResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if len(parsed.Hosts) != 0 {
					t.Errorf("expected 0 hosts, got %d", len(parsed.Hosts))
				}
			},
		},
		{
			name:    "invalid XML",
			input:   []byte(`not valid xml at all`),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte(``),
			wantErr: true,
		},
		{
			name:    "truncated XML",
			input:   []byte(`<?xml version="1.0"?><nmaprun scanner="nmap"`),
			wantErr: true,
		},
	}

	p := &NmapXMLParser{}
	if p.Name() != "nmap_xml" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "nmap_xml")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestNucleiJSONParser(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		checkFunc func(t *testing.T, raw json.RawMessage)
	}{
		{
			name: "multiple findings",
			input: []byte(`{"template-id":"tech-detect","info":{"name":"Tech Detection","severity":"info"},"host":"https://example.com","matched-at":"https://example.com","type":"http","ip":"93.184.216.34","url":"https://example.com"}
{"template-id":"cve-2024-1234","info":{"name":"Critical RCE","severity":"critical"},"host":"https://example.com","matched-at":"https://example.com/vuln","type":"http","ip":"93.184.216.34","url":"https://example.com/vuln","matched":"vulnerable pattern","extracted-results":["secret123"]}
`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nucleiResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalFindings != 2 {
					t.Fatalf("total_findings = %d, want 2", parsed.TotalFindings)
				}
				f0 := parsed.Findings[0]
				if f0.TemplateID != "tech-detect" {
					t.Errorf("findings[0].template_id = %q, want %q", f0.TemplateID, "tech-detect")
				}
				if f0.Name != "Tech Detection" {
					t.Errorf("findings[0].name = %q, want %q", f0.Name, "Tech Detection")
				}
				if f0.Severity != "info" {
					t.Errorf("findings[0].severity = %q, want %q", f0.Severity, "info")
				}
				if f0.Host != "https://example.com" {
					t.Errorf("findings[0].host = %q, want %q", f0.Host, "https://example.com")
				}
				if f0.IP != "93.184.216.34" {
					t.Errorf("findings[0].ip = %q, want %q", f0.IP, "93.184.216.34")
				}

				f1 := parsed.Findings[1]
				if f1.Severity != "critical" {
					t.Errorf("findings[1].severity = %q, want %q", f1.Severity, "critical")
				}
				if f1.Matched != "vulnerable pattern" {
					t.Errorf("findings[1].matched = %q, want %q", f1.Matched, "vulnerable pattern")
				}
				if len(f1.ExtractedResults) != 1 || f1.ExtractedResults[0] != "secret123" {
					t.Errorf("findings[1].extracted_results = %v, want [secret123]", f1.ExtractedResults)
				}
			},
		},
		{
			name:    "empty lines are skipped",
			input:   []byte("\n\n{\"template-id\":\"test\",\"info\":{\"name\":\"Test\",\"severity\":\"low\"},\"host\":\"http://test.com\",\"type\":\"http\"}\n\n"),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nucleiResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalFindings != 1 {
					t.Errorf("total_findings = %d, want 1", parsed.TotalFindings)
				}
			},
		},
		{
			name:    "invalid JSON lines are skipped",
			input:   []byte("not json\n{\"template-id\":\"valid\",\"info\":{\"name\":\"Valid\",\"severity\":\"medium\"},\"host\":\"http://x.com\",\"type\":\"http\"}\nalso not json\n"),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nucleiResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalFindings != 1 {
					t.Errorf("total_findings = %d, want 1 (invalid lines should be skipped)", parsed.TotalFindings)
				}
				if parsed.Findings[0].TemplateID != "valid" {
					t.Errorf("findings[0].template_id = %q, want %q", parsed.Findings[0].TemplateID, "valid")
				}
			},
		},
		{
			name:    "completely empty input",
			input:   []byte(``),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nucleiResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalFindings != 0 {
					t.Errorf("total_findings = %d, want 0", parsed.TotalFindings)
				}
			},
		},
		{
			name:    "all lines invalid JSON produces zero findings",
			input:   []byte("garbage line 1\ngarbage line 2\n"),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed nucleiResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalFindings != 0 {
					t.Errorf("total_findings = %d, want 0", parsed.TotalFindings)
				}
			},
		},
	}

	p := &NucleiJSONParser{}
	if p.Name() != "nuclei_json" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "nuclei_json")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestMasscanJSONParser(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		checkFunc func(t *testing.T, raw json.RawMessage)
	}{
		{
			name: "multiple entries with host merging",
			input: []byte(`[
				{"ip":"10.0.0.1","ports":[{"port":80,"proto":"tcp","status":"open","ttl":54}]},
				{"ip":"10.0.0.1","ports":[{"port":443,"proto":"tcp","status":"open","ttl":54}]},
				{"ip":"10.0.0.2","ports":[{"port":22,"proto":"tcp","status":"open","ttl":60}]}
			]`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed masscanResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalHosts != 2 {
					t.Errorf("total_hosts = %d, want 2", parsed.TotalHosts)
				}

				hostPorts := make(map[string]int)
				for _, h := range parsed.Hosts {
					hostPorts[h.Address] = len(h.Ports)
				}
				if hostPorts["10.0.0.1"] != 2 {
					t.Errorf("host 10.0.0.1 port count = %d, want 2 (merged)", hostPorts["10.0.0.1"])
				}
				if hostPorts["10.0.0.2"] != 1 {
					t.Errorf("host 10.0.0.2 port count = %d, want 1", hostPorts["10.0.0.2"])
				}
			},
		},
		{
			name:    "single host single port",
			input:   []byte(`[{"ip":"172.16.0.1","ports":[{"port":8080,"proto":"tcp","status":"open","ttl":128}]}]`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed masscanResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalHosts != 1 {
					t.Fatalf("total_hosts = %d, want 1", parsed.TotalHosts)
				}
				h := parsed.Hosts[0]
				if h.Address != "172.16.0.1" {
					t.Errorf("address = %q, want %q", h.Address, "172.16.0.1")
				}
				if len(h.Ports) != 1 {
					t.Fatalf("expected 1 port, got %d", len(h.Ports))
				}
				if h.Ports[0].Port != 8080 {
					t.Errorf("port = %d, want 8080", h.Ports[0].Port)
				}
				if h.Ports[0].Protocol != "tcp" {
					t.Errorf("protocol = %q, want %q", h.Ports[0].Protocol, "tcp")
				}
				if h.Ports[0].State != "open" {
					t.Errorf("state = %q, want %q", h.Ports[0].State, "open")
				}
				if h.Ports[0].TTL != 128 {
					t.Errorf("ttl = %d, want 128", h.Ports[0].TTL)
				}
			},
		},
		{
			name:    "empty array",
			input:   []byte(`[]`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed masscanResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalHosts != 0 {
					t.Errorf("total_hosts = %d, want 0", parsed.TotalHosts)
				}
			},
		},
		{
			name:    "entries with empty IP are skipped",
			input:   []byte(`[{"ip":"","ports":[{"port":80,"proto":"tcp","status":"open","ttl":50}]},{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open","ttl":64}]}]`),
			wantErr: false,
			checkFunc: func(t *testing.T, raw json.RawMessage) {
				var parsed masscanResult
				if err := json.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("unmarshal result: %v", err)
				}
				if parsed.TotalHosts != 1 {
					t.Errorf("total_hosts = %d, want 1 (empty IP skipped)", parsed.TotalHosts)
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   []byte(`not json at all`),
			wantErr: true,
		},
		{
			name:    "malformed JSON array",
			input:   []byte(`[{"ip":"10.0.0.1", broken`),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte(``),
			wantErr: true,
		},
	}

	p := &MasscanJSONParser{}
	if p.Name() != "masscan_json" {
		t.Fatalf("Name() = %q, want %q", p.Name(), "masscan_json")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestUnknownParserReturnsError(t *testing.T) {
	reg := NewRegistry()

	unknownNames := []string{"unknown", "nmap", "xml", "json", "masscan", ""}
	for _, name := range unknownNames {
		t.Run("lookup_"+name, func(t *testing.T) {
			p, ok := reg.Get(name)
			if ok {
				t.Errorf("Get(%q) returned ok=true, want false", name)
			}
			if p != nil {
				t.Errorf("Get(%q) returned non-nil parser, want nil", name)
			}
		})
	}
}

func TestRegistryRegisterCustomParser(t *testing.T) {
	reg := NewRegistry()

	// Verify custom parser can be registered and retrieved
	custom := &NmapXMLParser{} // reuse for test; Name() returns "nmap_xml"
	reg.Register(custom)

	p, ok := reg.Get("nmap_xml")
	if !ok {
		t.Fatal("expected registered parser to be retrievable")
	}
	if p != custom {
		t.Error("expected same parser instance back")
	}
}
