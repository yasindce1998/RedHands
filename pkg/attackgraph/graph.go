package attackgraph

import (
	"fmt"
	"strings"
	"sync"
)

// NodeType represents the type of a graph node.
type NodeType string

const (
	NodeHost       NodeType = "host"
	NodeService    NodeType = "service"
	NodeCredential NodeType = "credential"
	NodeFinding    NodeType = "finding"
	NodeObjective  NodeType = "objective"
)

// Node is a vertex in the attack graph.
type Node struct {
	ID       string            `json:"id"`
	Type     NodeType          `json:"type"`
	Label    string            `json:"label"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Edge connects two nodes with a relationship.
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Label  string `json:"label"`
	Weight int    `json:"weight"`
}

// Graph represents an attack graph with adjacency lists.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string][]Edge // adjacency: from -> []edges
}

// New creates an empty attack graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string][]Edge),
	}
}

// AddNode adds or updates a node.
func (g *Graph) AddNode(n *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = n
}

// AddEdge adds a directed edge.
func (g *Graph) AddEdge(from, to, label string, weight int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	e := Edge{From: from, To: to, Label: label, Weight: weight}
	g.edges[from] = append(g.edges[from], e)
}

// FindPath finds shortest path from source to target using BFS.
func (g *Graph) FindPath(source, target string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.nodes[source]; !ok {
		return nil
	}
	if _, ok := g.nodes[target]; !ok {
		return nil
	}

	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{source}
	visited[source] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == target {
			return g.reconstructPath(parent, source, target)
		}

		for _, edge := range g.edges[current] {
			if !visited[edge.To] {
				visited[edge.To] = true
				parent[edge.To] = current
				queue = append(queue, edge.To)
			}
		}
	}

	return nil
}

// FindAllPaths finds all paths up to maxDepth.
func (g *Graph) FindAllPaths(source, target string, maxDepth int) [][]string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if maxDepth <= 0 {
		maxDepth = 10
	}

	var paths [][]string
	visited := make(map[string]bool)
	g.dfs(source, target, visited, []string{source}, maxDepth, &paths)
	return paths
}

func (g *Graph) dfs(current, target string, visited map[string]bool, path []string, maxDepth int, paths *[][]string) {
	if len(path) > maxDepth {
		return
	}
	if current == target {
		cp := make([]string, len(path))
		copy(cp, path)
		*paths = append(*paths, cp)
		return
	}

	visited[current] = true
	defer func() { visited[current] = false }()

	for _, edge := range g.edges[current] {
		if !visited[edge.To] {
			g.dfs(edge.To, target, visited, append(path, edge.To), maxDepth, paths)
		}
	}
}

func (g *Graph) reconstructPath(parent map[string]string, source, target string) []*Node {
	var path []*Node
	current := target
	for current != source {
		path = append([]*Node{g.nodes[current]}, path...)
		current = parent[current]
	}
	path = append([]*Node{g.nodes[source]}, path...)
	return path
}

// Nodes returns all nodes.
func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}

// Edges returns all edges.
func (g *Graph) Edges() []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []Edge
	for _, edges := range g.edges {
		result = append(result, edges...)
	}
	return result
}

// ExportDOT exports the graph in Graphviz DOT format.
func (g *Graph) ExportDOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph AttackGraph {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box];\n\n")

	for _, n := range g.nodes {
		shape := "box"
		switch n.Type {
		case NodeHost:
			shape = "box"
		case NodeService:
			shape = "ellipse"
		case NodeCredential:
			shape = "diamond"
		case NodeFinding:
			shape = "hexagon"
		case NodeObjective:
			shape = "doubleoctagon"
		}
		fmt.Fprintf(&sb, "  %q [label=%q shape=%s];\n", n.ID, n.Label, shape)
	}

	sb.WriteString("\n")
	for _, edges := range g.edges {
		for _, e := range edges {
			fmt.Fprintf(&sb, "  %q -> %q [label=%q];\n", e.From, e.To, e.Label)
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ExportMermaid exports the graph in Mermaid diagram format.
func (g *Graph) ExportMermaid() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("graph LR\n")

	for _, n := range g.nodes {
		switch n.Type {
		case NodeObjective:
			fmt.Fprintf(&sb, "  %s((%s))\n", n.ID, n.Label)
		case NodeCredential:
			fmt.Fprintf(&sb, "  %s{%s}\n", n.ID, n.Label)
		default:
			fmt.Fprintf(&sb, "  %s[%s]\n", n.ID, n.Label)
		}
	}

	for _, edges := range g.edges {
		for _, e := range edges {
			fmt.Fprintf(&sb, "  %s -->|%s| %s\n", e.From, e.Label, e.To)
		}
	}

	return sb.String()
}

// ExportJSON exports nodes and edges as a JSON-friendly structure.
func (g *Graph) ExportJSON() map[string]interface{} {
	return map[string]interface{}{
		"nodes": g.Nodes(),
		"edges": g.Edges(),
	}
}

// Stats returns graph statistics.
func (g *Graph) Stats() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edgeCount := 0
	for _, edges := range g.edges {
		edgeCount += len(edges)
	}

	return map[string]int{
		"nodes": len(g.nodes),
		"edges": edgeCount,
	}
}
