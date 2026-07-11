package attackgraph

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAddNode(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "h1", Type: NodeHost, Label: "Server1"})
	g.AddNode(&Node{ID: "s1", Type: NodeService, Label: "SSH"})

	nodes := g.Nodes()
	if len(nodes) != 2 {
		t.Errorf("Nodes() = %d, want 2", len(nodes))
	}
}

func TestAddNode_Overwrite(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "h1", Type: NodeHost, Label: "Old"})
	g.AddNode(&Node{ID: "h1", Type: NodeHost, Label: "New"})

	nodes := g.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("duplicate ID should overwrite, got %d nodes", len(nodes))
	}
	if nodes[0].Label != "New" {
		t.Errorf("label = %q, want %q", nodes[0].Label, "New")
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddEdge("a", "b", "exploits", 5)

	edges := g.Edges()
	if len(edges) != 1 {
		t.Fatalf("Edges() = %d, want 1", len(edges))
	}
	if edges[0].From != "a" || edges[0].To != "b" || edges[0].Label != "exploits" || edges[0].Weight != 5 {
		t.Errorf("edge = %+v", edges[0])
	}
}

func TestFindPath_Direct(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddEdge("a", "b", "lateral", 1)

	path := g.FindPath("a", "b")
	if len(path) != 2 {
		t.Fatalf("path len = %d, want 2", len(path))
	}
	if path[0].ID != "a" || path[1].ID != "b" {
		t.Errorf("path = [%s, %s]", path[0].ID, path[1].ID)
	}
}

func TestFindPath_MultiHop(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddNode(&Node{ID: "c", Type: NodeHost, Label: "C"})
	g.AddEdge("a", "b", "e1", 1)
	g.AddEdge("b", "c", "e2", 1)

	path := g.FindPath("a", "c")
	if len(path) != 3 {
		t.Fatalf("path len = %d, want 3", len(path))
	}
	if path[0].ID != "a" || path[1].ID != "b" || path[2].ID != "c" {
		t.Error("wrong path order")
	}
}

func TestFindPath_NoPath(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})

	path := g.FindPath("a", "b")
	if path != nil {
		t.Errorf("expected nil path, got %v", path)
	}
}

func TestFindPath_UnknownNode(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})

	if g.FindPath("a", "z") != nil {
		t.Error("unknown target should return nil")
	}
	if g.FindPath("z", "a") != nil {
		t.Error("unknown source should return nil")
	}
}

func TestFindAllPaths(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddNode(&Node{ID: "c", Type: NodeHost, Label: "C"})
	g.AddEdge("a", "b", "e1", 1)
	g.AddEdge("a", "c", "e2", 1)
	g.AddEdge("b", "c", "e3", 1)

	paths := g.FindAllPaths("a", "c", 5)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
}

func TestFindAllPaths_MaxDepth(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddNode(&Node{ID: "c", Type: NodeHost, Label: "C"})
	g.AddNode(&Node{ID: "d", Type: NodeHost, Label: "D"})
	g.AddEdge("a", "b", "e1", 1)
	g.AddEdge("b", "c", "e2", 1)
	g.AddEdge("c", "d", "e3", 1)

	paths := g.FindAllPaths("a", "d", 2)
	if len(paths) != 0 {
		t.Errorf("depth 2 should not reach d (need 4 nodes in path), got %d paths", len(paths))
	}

	paths = g.FindAllPaths("a", "d", 5)
	if len(paths) != 1 {
		t.Errorf("depth 5 should find 1 path, got %d", len(paths))
	}
}

func TestExportDOT(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "h1", Type: NodeHost, Label: "Server"})
	g.AddNode(&Node{ID: "s1", Type: NodeService, Label: "SSH"})
	g.AddEdge("h1", "s1", "runs", 1)

	dot := g.ExportDOT()
	if !strings.Contains(dot, "digraph AttackGraph") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(dot, `"h1"`) {
		t.Error("missing node h1")
	}
	if !strings.Contains(dot, `"h1" -> "s1"`) {
		t.Error("missing edge")
	}
	if !strings.Contains(dot, "shape=ellipse") {
		t.Error("service should use ellipse shape")
	}
}

func TestExportMermaid(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "h1", Type: NodeHost, Label: "Server"})
	g.AddNode(&Node{ID: "obj", Type: NodeObjective, Label: "Root"})
	g.AddEdge("h1", "obj", "pwn", 1)

	mermaid := g.ExportMermaid()
	if !strings.Contains(mermaid, "graph LR") {
		t.Error("missing header")
	}
	if !strings.Contains(mermaid, "h1[Server]") {
		t.Error("missing host node")
	}
	if !strings.Contains(mermaid, "obj((Root))") {
		t.Error("objective should use (())")
	}
	if !strings.Contains(mermaid, "-->|pwn|") {
		t.Error("missing edge label")
	}
}

func TestExportJSON(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddEdge("a", "b", "test", 1)

	export := g.ExportJSON()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(data), `"nodes"`) || !strings.Contains(string(data), `"edges"`) {
		t.Error("export should contain nodes and edges keys")
	}
}

func TestStats(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "a", Type: NodeHost, Label: "A"})
	g.AddNode(&Node{ID: "b", Type: NodeHost, Label: "B"})
	g.AddEdge("a", "b", "e", 1)
	g.AddEdge("b", "a", "e2", 1)

	stats := g.Stats()
	if stats["nodes"] != 2 {
		t.Errorf("nodes = %d, want 2", stats["nodes"])
	}
	if stats["edges"] != 2 {
		t.Errorf("edges = %d, want 2", stats["edges"])
	}
}
