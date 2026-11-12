package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type ReportInput struct {
	Events   string `json:"events"`
	Out      string `json:"out,omitempty"`
	HTML     bool   `json:"html,omitempty"`
	Title    string `json:"title,omitempty"`
	Operator string `json:"operator,omitempty"`
	Client   string `json:"client,omitempty"`
	Start    string `json:"start,omitempty"`
	End      string `json:"end,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type ReportTool struct {
	exec executor.Executor
}

func NewReport(exec executor.Executor) *ReportTool {
	return &ReportTool{exec: exec}
}

func (t *ReportTool) Name() string { return "kubedagger_report" }

func (t *ReportTool) Description() string {
	return "Generate an engagement report from collected KubeDagger events. Requires a path to an events.jsonl file; supports HTML output, custom titles, operator/client attribution, and time/scope filtering."
}

func (t *ReportTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"events": {
				"type": "string",
				"description": "Path to the events.jsonl file (required)"
			},
			"out": {
				"type": "string",
				"description": "Output file path (default: stdout)"
			},
			"html": {
				"type": "boolean",
				"description": "Emit an HTML report instead of plain text"
			},
			"title": {
				"type": "string",
				"description": "Report title"
			},
			"operator": {
				"type": "string",
				"description": "Operator name to attribute the report to"
			},
			"client": {
				"type": "string",
				"description": "Client name for the report"
			},
			"start": {
				"type": "string",
				"description": "Start timestamp for the reporting window"
			},
			"end": {
				"type": "string",
				"description": "End timestamp for the reporting window"
			},
			"scope": {
				"type": "string",
				"description": "Scope filter for included events"
			}
		},
		"required": ["events"]
	}`)
}

func (t *ReportTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ReportInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Events == "" {
		return errorResult("events is required"), nil
	}
	stringFields := []struct {
		value string
		name  string
	}{
		{input.Events, "events"},
		{input.Out, "out"},
		{input.Title, "title"},
		{input.Operator, "operator"},
		{input.Client, "client"},
		{input.Start, "start"},
		{input.End, "end"},
		{input.Scope, "scope"},
	}
	for _, f := range stringFields {
		if err := validateSafeString(f.value, f.name); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"report", "generate", "--events", input.Events}
	if input.Out != "" {
		args = append(args, "--out", input.Out)
	}
	if input.HTML {
		args = append(args, "--html")
	}
	if input.Title != "" {
		args = append(args, "--title", input.Title)
	}
	if input.Operator != "" {
		args = append(args, "--operator", input.Operator)
	}
	if input.Client != "" {
		args = append(args, "--client", input.Client)
	}
	if input.Start != "" {
		args = append(args, "--start", input.Start)
	}
	if input.End != "" {
		args = append(args, "--end", input.End)
	}
	if input.Scope != "" {
		args = append(args, "--scope", input.Scope)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger report generate failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## KubeDagger Report\n\n")
	fmt.Fprintf(&sb, "Events: %s\n\n", input.Events)
	if output == "" {
		if input.Out != "" {
			fmt.Fprintf(&sb, "Report written to %s\n", input.Out)
		} else {
			sb.WriteString("Report generated (no output).\n")
		}
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
