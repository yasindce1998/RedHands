package targetdb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAddHost_New(t *testing.T) {
	s := NewStore("", false)

	err := s.AddHost(&Host{IP: "10.0.0.1", Hostname: "web01", OS: "Linux"})
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	h, ok := s.GetHost("10.0.0.1")
	if !ok {
		t.Fatal("host not found after add")
	}
	if h.Hostname != "web01" || h.OS != "Linux" {
		t.Errorf("got hostname=%q os=%q", h.Hostname, h.OS)
	}
	if h.FirstSeen.IsZero() || h.LastSeen.IsZero() {
		t.Error("timestamps not set")
	}
}

func TestAddHost_Merge(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddHost(&Host{IP: "10.0.0.1", Hostname: "web01", Tags: []string{"dmz"}})
	_ = s.AddHost(&Host{IP: "10.0.0.1", OS: "Ubuntu", Tags: []string{"web"}})

	h, _ := s.GetHost("10.0.0.1")
	if h.Hostname != "web01" {
		t.Errorf("hostname should remain: got %q", h.Hostname)
	}
	if h.OS != "Ubuntu" {
		t.Errorf("OS should update: got %q", h.OS)
	}
	if len(h.Tags) != 2 {
		t.Errorf("tags should merge: got %v", h.Tags)
	}
}

func TestAddService_NewAndMerge(t *testing.T) {
	s := NewStore("", false)

	_ = s.AddService(&Service{Host: "10.0.0.1", Port: 80, Protocol: "tcp", Name: "http"})
	_ = s.AddService(&Service{Host: "10.0.0.1", Port: 80, Protocol: "tcp", Version: "nginx/1.21"})

	svcs := s.ListServices("10.0.0.1")
	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if svcs[0].Name != "http" || svcs[0].Version != "nginx/1.21" {
		t.Errorf("merge failed: name=%q version=%q", svcs[0].Name, svcs[0].Version)
	}
}

func TestAddService_DifferentPort(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddService(&Service{Host: "10.0.0.1", Port: 80, Protocol: "tcp"})
	_ = s.AddService(&Service{Host: "10.0.0.1", Port: 443, Protocol: "tcp"})

	svcs := s.ListServices("10.0.0.1")
	if len(svcs) != 2 {
		t.Fatalf("expected 2 services, got %d", len(svcs))
	}
}

func TestAddCredential_Dedup(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddCredential(&Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Domain: "corp", Secret: "pass1", Source: "brute"})
	_ = s.AddCredential(&Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Domain: "corp", Secret: "pass2", Source: "kerberoast"})

	creds := s.ListCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Secret != "pass2" {
		t.Errorf("secret should update: got %q", creds[0].Secret)
	}
	if creds[0].Source != "kerberoast" {
		t.Errorf("source should update: got %q", creds[0].Source)
	}
}

func TestAddFinding_AutoFields(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddFinding(&Finding{Host: "10.0.0.1", Tool: "nmap", Severity: "high", Title: "Open SMB"})

	findings := s.ListFindings()
	if len(findings) != 1 {
		t.Fatal("expected 1 finding")
	}
	if findings[0].ID == "" {
		t.Error("ID should be auto-generated")
	}
	if findings[0].Timestamp.IsZero() {
		t.Error("Timestamp should be auto-set")
	}
}

func TestQueryFindings(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddFinding(&Finding{Host: "10.0.0.1", Tool: "nmap", Severity: "high", Title: "A"})
	_ = s.AddFinding(&Finding{Host: "10.0.0.1", Tool: "nikto", Severity: "medium", Title: "B"})
	_ = s.AddFinding(&Finding{Host: "10.0.0.2", Tool: "nmap", Severity: "high", Title: "C"})

	tests := []struct {
		host, sev, tool string
		want            int
	}{
		{"10.0.0.1", "", "", 2},
		{"", "high", "", 2},
		{"", "", "nmap", 2},
		{"10.0.0.1", "high", "nmap", 1},
		{"10.0.0.99", "", "", 0},
	}
	for _, tc := range tests {
		got := s.QueryFindings(tc.host, tc.sev, tc.tool)
		if len(got) != tc.want {
			t.Errorf("QueryFindings(%q,%q,%q) = %d results, want %d", tc.host, tc.sev, tc.tool, len(got), tc.want)
		}
	}
}

func TestPersistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")

	s1 := NewStore(path, true)
	_ = s1.AddHost(&Host{IP: "10.0.0.1", Hostname: "web01"})
	_ = s1.AddService(&Service{Host: "10.0.0.1", Port: 80, Protocol: "tcp"})
	_ = s1.AddCredential(&Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Secret: "x"})
	_ = s1.AddFinding(&Finding{Host: "10.0.0.1", Tool: "test", Severity: "low", Title: "T"})

	s2 := NewStore(path, false)
	if _, ok := s2.GetHost("10.0.0.1"); !ok {
		t.Error("host not persisted")
	}
	if len(s2.ListServices("10.0.0.1")) != 1 {
		t.Error("service not persisted")
	}
	if len(s2.ListCredentials()) != 1 {
		t.Error("credential not persisted")
	}
	if len(s2.ListFindings()) != 1 {
		t.Error("finding not persisted")
	}
}

func TestPersistence_MissingFile(t *testing.T) {
	s := NewStore("/nonexistent/path/db.json", false)
	hosts := s.ListHosts()
	if len(hosts) != 0 {
		t.Error("expected empty store for missing file")
	}
}

func TestStats(t *testing.T) {
	s := NewStore("", false)
	_ = s.AddHost(&Host{IP: "10.0.0.1"})
	_ = s.AddHost(&Host{IP: "10.0.0.2"})
	_ = s.AddService(&Service{Host: "10.0.0.1", Port: 80, Protocol: "tcp"})

	stats := s.Stats()
	if stats["hosts"] != 2 {
		t.Errorf("hosts = %d, want 2", stats["hosts"])
	}
	if stats["services"] != 1 {
		t.Errorf("services = %d, want 1", stats["services"])
	}
}

func TestSave_ExplicitSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.json")

	s := NewStore(path, false)
	_ = s.AddHost(&Host{IP: "10.0.0.1"})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist before explicit save")
	}

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file should exist after save")
	}
}
