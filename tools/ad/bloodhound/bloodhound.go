package bloodhound

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// CollectTool - bloodhound_collect
// ---------------------------------------------------------------------------

type CollectInput struct {
	Domain           string `json:"domain"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	DC               string `json:"dc,omitempty"`
	CollectionMethod string `json:"collection_method,omitempty"`
	NSServer         string `json:"ns_server,omitempty"`
	OutputDir        string `json:"output_dir,omitempty"`
}

type CollectTool struct {
	exec executor.Executor
}

func NewCollect(exec executor.Executor) *CollectTool {
	return &CollectTool{exec: exec}
}

func (t *CollectTool) Name() string { return "bloodhound_collect" }

func (t *CollectTool) Description() string {
	return "Run BloodHound data collection (bloodhound-python) to enumerate Active Directory objects, relationships, sessions, ACLs, and trusts for attack path analysis."
}

func (t *CollectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"domain": {
				"type": "string",
				"description": "Target Active Directory domain (e.g. corp.local)"
			},
			"username": {
				"type": "string",
				"description": "Domain username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"dc": {
				"type": "string",
				"description": "Domain controller hostname or IP"
			},
			"collection_method": {
				"type": "string",
				"description": "Collection method to use",
				"enum": ["All", "Default", "Session", "LoggedOn", "ACL", "Trusts", "Group", "ObjectProps"]
			},
			"ns_server": {
				"type": "string",
				"description": "Alternative nameserver for DNS resolution"
			},
			"output_dir": {
				"type": "string",
				"description": "Output directory for collected JSON files"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *CollectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CollectInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Domain); err != nil {
		return errorResult("domain: " + err.Error()), nil
	}

	args := []string{"-d", input.Domain}

	if input.Username != "" {
		if err := validateInput(input.Username); err != nil {
			return errorResult("username: " + err.Error()), nil
		}
		args = append(args, "-u", input.Username)
	}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult("password: " + err.Error()), nil
		}
		args = append(args, "-p", input.Password)
	}
	if input.DC != "" {
		if err := validateInput(input.DC); err != nil {
			return errorResult("dc: " + err.Error()), nil
		}
		args = append(args, "-dc", input.DC)
	}
	if input.CollectionMethod != "" {
		args = append(args, "-c", input.CollectionMethod)
	}
	if input.NSServer != "" {
		if err := validateInput(input.NSServer); err != nil {
			return errorResult("ns_server: " + err.Error()), nil
		}
		args = append(args, "--nameserver", input.NSServer)
	}
	if input.OutputDir != "" {
		if err := validateInput(input.OutputDir); err != nil {
			return errorResult("output_dir: " + err.Error()), nil
		}
		args = append(args, "-o", input.OutputDir)
	}

	result, err := t.exec.Run(ctx, "bloodhound-python", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("bloodhound collection failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## BloodHound Collection\n\n")
	fmt.Fprintf(&sb, "**Domain**: %s\n", input.Domain)
	if input.CollectionMethod != "" {
		fmt.Fprintf(&sb, "**Method**: %s\n", input.CollectionMethod)
	}
	sb.WriteString("\n")
	if output == "" {
		sb.WriteString("Collection completed with no output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// FindPathTool - bloodhound_find_path
// ---------------------------------------------------------------------------

type FindPathInput struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	DatabaseURI string `json:"database_uri,omitempty"`
}

type FindPathTool struct {
	exec executor.Executor
}

func NewFindPath(exec executor.Executor) *FindPathTool {
	return &FindPathTool{exec: exec}
}

func (t *FindPathTool) Name() string { return "bloodhound_find_path" }

func (t *FindPathTool) Description() string {
	return "Query the BloodHound Neo4j database for shortest attack paths between two Active Directory principals (e.g. from a compromised user to Domain Admins)."
}

func (t *FindPathTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source": {
				"type": "string",
				"description": "Source node (e.g. USER@DOMAIN.LOCAL)"
			},
			"target": {
				"type": "string",
				"description": "Target node (e.g. Domain Admins)"
			},
			"database_uri": {
				"type": "string",
				"description": "Neo4j database URI (default: bolt://localhost:7687)"
			}
		},
		"required": ["source", "target"]
	}`)
}

func (t *FindPathTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input FindPathInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Source); err != nil {
		return errorResult("source: " + err.Error()), nil
	}
	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}

	query := fmt.Sprintf(
		"MATCH p=shortestPath((s {name:%q})-[*1..]->(t {name:%q})) RETURN p",
		input.Source, input.Target,
	)

	args := []string{"--query", query}

	if input.DatabaseURI != "" {
		if err := validateInput(input.DatabaseURI); err != nil {
			return errorResult("database_uri: " + err.Error()), nil
		}
		args = append(args, "--database-uri", input.DatabaseURI)
	}

	result, err := t.exec.Run(ctx, "bloodhound-python", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("path query failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## BloodHound Attack Path\n\n")
	fmt.Fprintf(&sb, "**Source**: %s\n", input.Source)
	fmt.Fprintf(&sb, "**Target**: %s\n\n", input.Target)
	if output == "" {
		sb.WriteString("No path found between source and target.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// MarkOwnedTool - bloodhound_mark_owned
// ---------------------------------------------------------------------------

type MarkOwnedInput struct {
	Node        string `json:"node"`
	DatabaseURI string `json:"database_uri,omitempty"`
}

type MarkOwnedTool struct {
	exec executor.Executor
}

func NewMarkOwned(exec executor.Executor) *MarkOwnedTool {
	return &MarkOwnedTool{exec: exec}
}

func (t *MarkOwnedTool) Name() string { return "bloodhound_mark_owned" }

func (t *MarkOwnedTool) Description() string {
	return "Mark an Active Directory node as owned/compromised in the BloodHound database to update attack path calculations."
}

func (t *MarkOwnedTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"node": {
				"type": "string",
				"description": "Node name to mark as owned (e.g. USER@DOMAIN.LOCAL)"
			},
			"database_uri": {
				"type": "string",
				"description": "Neo4j database URI (default: bolt://localhost:7687)"
			}
		},
		"required": ["node"]
	}`)
}

func (t *MarkOwnedTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input MarkOwnedInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Node); err != nil {
		return errorResult("node: " + err.Error()), nil
	}

	query := fmt.Sprintf(
		"MATCH (n {name:%q}) SET n.owned=true RETURN n.name",
		input.Node,
	)

	args := []string{"--query", query}

	if input.DatabaseURI != "" {
		if err := validateInput(input.DatabaseURI); err != nil {
			return errorResult("database_uri: " + err.Error()), nil
		}
		args = append(args, "--database-uri", input.DatabaseURI)
	}

	result, err := t.exec.Run(ctx, "bloodhound-python", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("mark owned failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## BloodHound Mark Owned\n\n")
	fmt.Fprintf(&sb, "**Node**: %s\n", input.Node)
	sb.WriteString("**Status**: Marked as owned\n\n")
	if output != "" {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// ---------------------------------------------------------------------------
// AnalyzeTool - bloodhound_analyze
// ---------------------------------------------------------------------------

type AnalyzeInput struct {
	QueryType   string `json:"query_type"`
	DatabaseURI string `json:"database_uri,omitempty"`
}

type AnalyzeTool struct {
	exec executor.Executor
}

func NewAnalyze(exec executor.Executor) *AnalyzeTool {
	return &AnalyzeTool{exec: exec}
}

func (t *AnalyzeTool) Name() string { return "bloodhound_analyze" }

func (t *AnalyzeTool) Description() string {
	return "Run pre-built analysis queries against BloodHound data to identify kerberoastable users, AS-REP roastable accounts, unconstrained delegation, high-value targets, or shortest paths to Domain Admins."
}

func (t *AnalyzeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"query_type": {
				"type": "string",
				"description": "Type of analysis query to run",
				"enum": ["kerberoastable", "asreproastable", "unconstrained_delegation", "high_value_targets", "shortest_path_to_da"]
			},
			"database_uri": {
				"type": "string",
				"description": "Neo4j database URI (default: bolt://localhost:7687)"
			}
		},
		"required": ["query_type"]
	}`)
}

var analyzeQueries = map[string]string{
	"kerberoastable":          "MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames",
	"asreproastable":          "MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name",
	"unconstrained_delegation": "MATCH (c:Computer) WHERE c.unconstraineddelegation=true RETURN c.name",
	"high_value_targets":      "MATCH (n) WHERE n.highvalue=true RETURN n.name, labels(n)",
	"shortest_path_to_da":     "MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p",
}

func (t *AnalyzeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input AnalyzeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.QueryType == "" {
		return errorResult("query_type is required"), nil
	}

	query, ok := analyzeQueries[input.QueryType]
	if !ok {
		return errorResult(fmt.Sprintf("unknown query_type: %s", input.QueryType)), nil
	}

	args := []string{"--query", query}

	if input.DatabaseURI != "" {
		if err := validateInput(input.DatabaseURI); err != nil {
			return errorResult("database_uri: " + err.Error()), nil
		}
		args = append(args, "--database-uri", input.DatabaseURI)
	}

	result, err := t.exec.Run(ctx, "bloodhound-python", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("analysis query failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## BloodHound Analysis\n\n")
	fmt.Fprintf(&sb, "**Query**: %s\n\n", input.QueryType)
	if output == "" {
		sb.WriteString("No results found.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}
