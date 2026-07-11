package opsec

import (
	"path/filepath"
	"testing"
)

func TestTracker_Record_And_List(t *testing.T) {
	tr := NewTracker("")
	tr.Record("nmap", "10.0.0.1", "scan", "port scan")
	tr.Record("nikto", "10.0.0.2", "web_scan", "web scan")

	iocs := tr.List()
	if len(iocs) != 2 {
		t.Fatalf("List() = %d, want 2", len(iocs))
	}
	if iocs[0].Tool != "nmap" || iocs[0].Target != "10.0.0.1" {
		t.Errorf("first IOC = %+v", iocs[0])
	}
}

func TestTracker_ListByTool(t *testing.T) {
	tr := NewTracker("")
	tr.Record("nmap", "10.0.0.1", "scan", "v1")
	tr.Record("nikto", "10.0.0.2", "web", "v2")
	tr.Record("nmap", "10.0.0.3", "scan", "v3")

	got := tr.ListByTool("nmap")
	if len(got) != 2 {
		t.Errorf("ListByTool(nmap) = %d, want 2", len(got))
	}
}

func TestTracker_Count(t *testing.T) {
	tr := NewTracker("")
	if tr.Count() != 0 {
		t.Error("empty tracker should have count 0")
	}
	tr.Record("x", "y", "z", "w")
	if tr.Count() != 1 {
		t.Errorf("count = %d, want 1", tr.Count())
	}
}

func TestTracker_Clear(t *testing.T) {
	tr := NewTracker("")
	tr.Record("a", "b", "c", "d")
	tr.Record("e", "f", "g", "h")
	tr.Clear()

	if tr.Count() != 0 {
		t.Errorf("after Clear, count = %d", tr.Count())
	}
	if len(tr.List()) != 0 {
		t.Error("after Clear, List should be empty")
	}
}

func TestTracker_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iocs.json")

	tr1 := NewTracker(path)
	tr1.Record("nmap", "10.0.0.1", "scan", "port_scan")
	tr1.Record("hydra", "10.0.0.2", "brute", "ssh_brute")

	tr2 := NewTracker(path)
	if tr2.Count() != 2 {
		t.Errorf("reloaded count = %d, want 2", tr2.Count())
	}
	iocs := tr2.List()
	if iocs[0].Tool != "nmap" {
		t.Errorf("first ioc tool = %q", iocs[0].Tool)
	}
}

func TestTracker_Clear_PersistsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "iocs.json")

	tr1 := NewTracker(path)
	tr1.Record("a", "b", "c", "d")
	tr1.Clear()

	tr2 := NewTracker(path)
	if tr2.Count() != 0 {
		t.Errorf("after clear+reload, count = %d", tr2.Count())
	}
}

func TestTracker_ListReturnsSnapshot(t *testing.T) {
	tr := NewTracker("")
	tr.Record("a", "b", "c", "d")

	list := tr.List()
	list[0].Tool = "modified"

	fresh := tr.List()
	if fresh[0].Tool == "modified" {
		t.Error("List should return a copy, not a reference")
	}
}
