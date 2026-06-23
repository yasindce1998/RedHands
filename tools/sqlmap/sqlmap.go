package sqlmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type SQLMapInput struct {
	URL         string `json:"url"`
	Data        string `json:"data,omitempty"`
	Method      string `json:"method,omitempty"`
	Cookie      string `json:"cookie,omitempty"`
	Headers     string `json:"headers,omitempty"`
	Level       int    `json:"level,omitempty"`
	Risk        int    `json:"risk,omitempty"`
	DBs         bool   `json:"dbs,omitempty"`
	Tables      bool   `json:"tables,omitempty"`
	Columns     bool   `json:"columns,omitempty"`
	Dump        bool   `json:"dump,omitempty"`
	DB          string `json:"db,omitempty"`
	Table       string `json:"table,omitempty"`
	Technique   string `json:"technique,omitempty"`
	Tamper      string `json:"tamper,omitempty"`
	Threads     int    `json:"threads,omitempty"`
	BatchMode   bool   `json:"batch,omitempty"`
	Forms       bool   `json:"forms,omitempty"`
	CrawlDepth  int    `json:"crawl_depth,omitempty"`
	RandomAgent bool   `json:"random_agent,omitempty"`
}

type SQLMapTool struct {
	exec *executor.BinaryExecutor
}

func NewSQLMap(exec *executor.BinaryExecutor) *SQLMapTool {
	return &SQLMapTool{exec: exec}
}

func (t *SQLMapTool) Name() string { return "sqlmap_scan" }

func (t *SQLMapTool) Description() string {
	return "Automatic SQL injection detection and exploitation tool. Tests URL parameters, POST data, cookies, and headers for SQL injection vulnerabilities. Can enumerate databases, tables, and dump data."
}

func (t *SQLMapTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"url": {
				"type": "string",
				"description": "Target URL with parameter(s) to test (e.g., 'http://target.com/page?id=1')"
			},
			"data": {
				"type": "string",
				"description": "POST data string (e.g., 'user=admin&pass=test')"
			},
			"method": {
				"type": "string",
				"enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
				"description": "HTTP method to use"
			},
			"cookie": {
				"type": "string",
				"description": "HTTP Cookie header value"
			},
			"headers": {
				"type": "string",
				"description": "Extra headers (newline-separated, e.g., 'X-Token: abc\\nX-Custom: val')"
			},
			"level": {
				"type": "integer",
				"description": "Level of tests to perform (1-5, default 1)"
			},
			"risk": {
				"type": "integer",
				"description": "Risk of tests to perform (1-3, default 1)"
			},
			"dbs": {
				"type": "boolean",
				"description": "Enumerate DBMS databases"
			},
			"tables": {
				"type": "boolean",
				"description": "Enumerate tables for given database (-D required)"
			},
			"columns": {
				"type": "boolean",
				"description": "Enumerate columns for given table (-D and -T required)"
			},
			"dump": {
				"type": "boolean",
				"description": "Dump table entries (-D and -T required)"
			},
			"db": {
				"type": "string",
				"description": "Database to enumerate/dump from"
			},
			"table": {
				"type": "string",
				"description": "Table to enumerate/dump from"
			},
			"technique": {
				"type": "string",
				"description": "SQL injection techniques to use (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)"
			},
			"tamper": {
				"type": "string",
				"description": "Tamper script(s) to use (comma-separated, e.g., 'space2comment,between')"
			},
			"threads": {
				"type": "integer",
				"description": "Max number of concurrent HTTP requests (default: 1)"
			},
			"batch": {
				"type": "boolean",
				"description": "Never ask for user input, use default behavior"
			},
			"forms": {
				"type": "boolean",
				"description": "Parse and test forms on target URL"
			},
			"crawl_depth": {
				"type": "integer",
				"description": "Crawl the website starting from target URL (depth 1-10)"
			},
			"random_agent": {
				"type": "boolean",
				"description": "Use randomly selected HTTP User-Agent"
			}
		},
		"required": ["url"]
	}`)
}

func (t *SQLMapTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input SQLMapInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateURL(input.URL); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"-u", input.URL, "--batch", "--no-color"}

	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}
	if input.Method != "" {
		args = append(args, "--method", input.Method)
	}
	if input.Cookie != "" {
		args = append(args, "--cookie", input.Cookie)
	}
	if input.Headers != "" {
		for h := range strings.SplitSeq(input.Headers, "\n") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "-H", h)
			}
		}
	}
	if input.Level > 0 {
		args = append(args, "--level", fmt.Sprintf("%d", input.Level))
	}
	if input.Risk > 0 {
		args = append(args, "--risk", fmt.Sprintf("%d", input.Risk))
	}
	if input.DBs {
		args = append(args, "--dbs")
	}
	if input.Tables {
		args = append(args, "--tables")
	}
	if input.Columns {
		args = append(args, "--columns")
	}
	if input.Dump {
		args = append(args, "--dump")
	}
	if input.DB != "" {
		args = append(args, "-D", input.DB)
	}
	if input.Table != "" {
		args = append(args, "-T", input.Table)
	}
	if input.Technique != "" {
		args = append(args, "--technique", input.Technique)
	}
	if input.Tamper != "" {
		args = append(args, "--tamper", input.Tamper)
	}
	if input.Threads > 0 {
		args = append(args, "--threads", fmt.Sprintf("%d", input.Threads))
	}
	if input.Forms {
		args = append(args, "--forms")
	}
	if input.CrawlDepth > 0 {
		args = append(args, "--crawl", fmt.Sprintf("%d", input.CrawlDepth))
	}
	if input.RandomAgent {
		args = append(args, "--random-agent")
	}

	result, err := t.exec.Run(ctx, "sqlmap", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("sqlmap execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "## SQLMap Results: %s\n\n", input.URL)
	if output == "" {
		sb.WriteString("No output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func validateURL(u string) error {
	if u == "" {
		return fmt.Errorf("url is required")
	}
	if len(u) > 4096 {
		return fmt.Errorf("url too long")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}
	forbidden := []string{";", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(u, c) {
			return fmt.Errorf("url contains forbidden character: %q", c)
		}
	}
	return nil
}
