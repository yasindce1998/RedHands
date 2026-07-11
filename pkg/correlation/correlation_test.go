package correlation

import (
	"testing"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

func newTestStore() *targetdb.Store {
	return targetdb.NewStore("", false)
}

func TestEscalationChain_Triggered(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "critical", Title: "RCE", Tool: "exploit"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "high", Title: "LPE", Tool: "enum"})

	e := NewEngine(s)
	insights := e.Analyze()

	found := false
	for _, i := range insights {
		if i.Type == "escalation_chain" {
			found = true
			if i.Severity != "critical" {
				t.Errorf("severity = %q, want critical", i.Severity)
			}
			if len(i.Hosts) != 1 || i.Hosts[0] != "10.0.0.1" {
				t.Errorf("hosts = %v", i.Hosts)
			}
		}
	}
	if !found {
		t.Error("expected escalation_chain insight")
	}
}

func TestEscalationChain_BelowThreshold(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "critical", Title: "RCE", Tool: "x"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "low", Title: "Info", Tool: "x"})

	e := NewEngine(s)
	insights := e.Analyze()

	for _, i := range insights {
		if i.Type == "escalation_chain" {
			t.Error("should not trigger with only 1 crit/high finding")
		}
	}
}

func TestLateralMovement(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.2"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.2", Port: 445, Protocol: "tcp"})
	_ = s.AddCredential(&targetdb.Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Secret: "pw", Valid: true})

	e := NewEngine(s)
	insights := e.Analyze()

	found := false
	for _, i := range insights {
		if i.Type == "lateral_movement" {
			found = true
			if i.Severity != "high" {
				t.Errorf("severity = %q, want high", i.Severity)
			}
		}
	}
	if !found {
		t.Error("expected lateral_movement insight")
	}
}

func TestLateralMovement_InvalidCred(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.2"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.2", Port: 445, Protocol: "tcp"})
	_ = s.AddCredential(&targetdb.Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Secret: "pw", Valid: false})

	e := NewEngine(s)
	insights := e.Analyze()

	for _, i := range insights {
		if i.Type == "lateral_movement" {
			t.Error("invalid cred should not trigger lateral movement")
		}
	}
}

func TestHighRiskServices_Triggered(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.1", Port: 445, Protocol: "tcp"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.1", Port: 3389, Protocol: "tcp"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.1", Port: 22, Protocol: "tcp"})

	e := NewEngine(s)
	insights := e.Analyze()

	found := false
	for _, i := range insights {
		if i.Type == "high_risk_exposure" {
			found = true
		}
	}
	if !found {
		t.Error("expected high_risk_exposure with 3 risky ports")
	}
}

func TestHighRiskServices_BelowThreshold(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.1", Port: 445, Protocol: "tcp"})
	_ = s.AddService(&targetdb.Service{Host: "10.0.0.1", Port: 22, Protocol: "tcp"})

	e := NewEngine(s)
	insights := e.Analyze()

	for _, i := range insights {
		if i.Type == "high_risk_exposure" {
			t.Error("2 risky ports should not trigger (need >=3)")
		}
	}
}

func TestCredentialReuse(t *testing.T) {
	s := newTestStore()
	_ = s.AddCredential(&targetdb.Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Domain: "CORP", Secret: "x"})
	_ = s.AddCredential(&targetdb.Credential{Username: "admin", Host: "10.0.0.2", Type: "password", Domain: "CORP", Secret: "y"})

	e := NewEngine(s)
	insights := e.Analyze()

	found := false
	for _, i := range insights {
		if i.Type == "credential_reuse" {
			found = true
			if i.Severity != "medium" {
				t.Errorf("severity = %q, want medium", i.Severity)
			}
			if len(i.Hosts) != 2 {
				t.Errorf("hosts count = %d, want 2", len(i.Hosts))
			}
		}
	}
	if !found {
		t.Error("expected credential_reuse insight")
	}
}

func TestCredentialReuse_SingleHost(t *testing.T) {
	s := newTestStore()
	_ = s.AddCredential(&targetdb.Credential{Username: "admin", Host: "10.0.0.1", Type: "password", Domain: "CORP", Secret: "x"})

	e := NewEngine(s)
	insights := e.Analyze()

	for _, i := range insights {
		if i.Type == "credential_reuse" {
			t.Error("single host should not trigger reuse")
		}
	}
}

func TestAnalyze_SeveritySort(t *testing.T) {
	s := newTestStore()
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.1"})
	_ = s.AddHost(&targetdb.Host{IP: "10.0.0.2"})
	_ = s.AddCredential(&targetdb.Credential{Username: "u", Host: "10.0.0.1", Type: "t", Domain: "d", Secret: "a"})
	_ = s.AddCredential(&targetdb.Credential{Username: "u", Host: "10.0.0.2", Type: "t", Domain: "d", Secret: "b"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "critical", Title: "A", Tool: "x"})
	_ = s.AddFinding(&targetdb.Finding{Host: "10.0.0.1", Severity: "high", Title: "B", Tool: "x"})

	e := NewEngine(s)
	insights := e.Analyze()

	if len(insights) < 2 {
		t.Fatalf("expected at least 2 insights, got %d", len(insights))
	}
	if severityRank(insights[0].Severity) < severityRank(insights[len(insights)-1].Severity) {
		t.Errorf("insights not sorted by severity: first=%q last=%q", insights[0].Severity, insights[len(insights)-1].Severity)
	}
}

func TestAnalyze_Empty(t *testing.T) {
	s := newTestStore()
	e := NewEngine(s)
	insights := e.Analyze()
	if len(insights) != 0 {
		t.Errorf("empty store should yield no insights, got %d", len(insights))
	}
}
