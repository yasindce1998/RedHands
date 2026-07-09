package intelligence

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/attackgraph"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

// AttackGraphBuildTool builds an attack graph from the target database.
type AttackGraphBuildTool struct {
	store *targetdb.Store
	graph *attackgraph.Graph
}

func NewAttackGraphBuildTool(store *targetdb.Store, graph *attackgraph.Graph) *AttackGraphBuildTool {
	return &AttackGraphBuildTool{store: store, graph: graph}
}

func (t *AttackGraphBuildTool) Name() string { return "attackgraph_build" }

func (t *AttackGraphBuildTool) Description() string {
	return "Build an attack graph from the current target database (hosts, services, credentials, findings)"
}

func (t *AttackGraphBuildTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {}
	}`)
}

func (t *AttackGraphBuildTool) Execute(_ context.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
	hosts := t.store.ListHosts()
	services := t.store.ListServices("")
	creds := t.store.ListCredentials()
	findings := t.store.QueryFindings("", "", "")

	for _, h := range hosts {
		t.graph.AddNode(&attackgraph.Node{
			ID:    "host_" + h.IP,
			Type:  attackgraph.NodeHost,
			Label: fmt.Sprintf("%s (%s)", h.IP, h.Hostname),
			Metadata: map[string]string{"os": h.OS},
		})
	}

	for _, svc := range services {
		id := fmt.Sprintf("svc_%s_%d", svc.Host, svc.Port)
		t.graph.AddNode(&attackgraph.Node{
			ID:    id,
			Type:  attackgraph.NodeService,
			Label: fmt.Sprintf("%s:%d (%s)", svc.Host, svc.Port, svc.Name),
		})
		t.graph.AddEdge("host_"+svc.Host, id, "exposes", 1)
	}

	for _, c := range creds {
		id := fmt.Sprintf("cred_%s_%s", c.Domain, c.Username)
		t.graph.AddNode(&attackgraph.Node{
			ID:    id,
			Type:  attackgraph.NodeCredential,
			Label: fmt.Sprintf("%s\\%s", c.Domain, c.Username),
		})
		t.graph.AddEdge("host_"+c.Host, id, "yielded", 1)

		if c.Valid {
			for _, h := range hosts {
				if h.IP == c.Host {
					continue
				}
				for _, svc := range services {
					if svc.Host == h.IP && isAuthPort(svc.Port) {
						t.graph.AddEdge(id, "host_"+h.IP, "authenticates", 2)
						break
					}
				}
			}
		}
	}

	for _, f := range findings {
		id := "finding_" + f.ID
		t.graph.AddNode(&attackgraph.Node{
			ID:    id,
			Type:  attackgraph.NodeFinding,
			Label: f.Title,
			Metadata: map[string]string{"severity": f.Severity},
		})
		t.graph.AddEdge("host_"+f.Host, id, "has_vuln", severityWeight(f.Severity))
	}

	stats := t.graph.Stats()
	return textResult(fmt.Sprintf("Attack graph built: %d nodes, %d edges", stats["nodes"], stats["edges"]))
}

// AttackGraphPathTool finds attack paths between nodes.
type AttackGraphPathTool struct {
	graph *attackgraph.Graph
}

func NewAttackGraphPathTool(graph *attackgraph.Graph) *AttackGraphPathTool {
	return &AttackGraphPathTool{graph: graph}
}

func (t *AttackGraphPathTool) Name() string { return "attackgraph_path" }

func (t *AttackGraphPathTool) Description() string {
	return "Find attack paths between two nodes in the attack graph"
}

func (t *AttackGraphPathTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source": {"type": "string", "description": "Source node ID (e.g., host_10.0.0.1)"},
			"target": {"type": "string", "description": "Target node ID (e.g., host_10.0.0.5)"},
			"max_depth": {"type": "integer", "description": "Maximum path depth (default 10)"}
		},
		"required": ["source", "target"]
	}`)
}

func (t *AttackGraphPathTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		MaxDepth int    `json:"max_depth"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}
	if input.Source == "" || input.Target == "" {
		return errorResult("source and target are required")
	}

	paths := t.graph.FindAllPaths(input.Source, input.Target, input.MaxDepth)
	if len(paths) == 0 {
		return textResult(fmt.Sprintf("No path found from %s to %s", input.Source, input.Target))
	}

	return jsonResult(map[string]interface{}{
		"source": input.Source,
		"target": input.Target,
		"paths":  paths,
		"count":  len(paths),
	})
}

// AttackGraphExportTool exports the graph in various formats.
type AttackGraphExportTool struct {
	graph *attackgraph.Graph
}

func NewAttackGraphExportTool(graph *attackgraph.Graph) *AttackGraphExportTool {
	return &AttackGraphExportTool{graph: graph}
}

func (t *AttackGraphExportTool) Name() string { return "attackgraph_export" }

func (t *AttackGraphExportTool) Description() string {
	return "Export the attack graph in DOT, Mermaid, or JSON format"
}

func (t *AttackGraphExportTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"format": {
				"type": "string",
				"description": "Export format",
				"enum": ["dot", "mermaid", "json"]
			}
		},
		"required": ["format"]
	}`)
}

func (t *AttackGraphExportTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid params: " + err.Error())
	}

	switch input.Format {
	case "dot":
		return textResult(t.graph.ExportDOT())
	case "mermaid":
		return textResult(t.graph.ExportMermaid())
	case "json":
		return jsonResult(t.graph.ExportJSON())
	default:
		return errorResult("unsupported format: " + input.Format + " (use dot, mermaid, or json)")
	}
}

func isAuthPort(port int) bool {
	switch port {
	case 22, 445, 3389, 5985, 5986, 1433, 3306, 5432, 389, 636:
		return true
	}
	return false
}

func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
