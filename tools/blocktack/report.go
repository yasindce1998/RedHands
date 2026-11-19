package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ReportTool runs `blocktack report`: merges findings JSON files into a
// markdown report, optionally engagement-grade (executive summary, kill
// chains, remediation guidance).
type ReportTool struct {
	exec executor.Executor
}

// NewReport constructs the blocktack_report tool.
func NewReport(exec executor.Executor) *ReportTool {
	return &ReportTool{exec: exec}
}

func (t *ReportTool) Name() string { return "blocktack_report" }

func (t *ReportTool) Description() string {
	return "Generate a markdown report from BlockTack findings JSON files (blocktack report): pass one or more findings.json paths (for example from blocktack_campaign_results or recon/scan outputs). With engagement=true the report is a client-ready deliverable (executive summary, kill chains with financial blast radius, remediation guidance) and accepts the target YAML and killchains.json for context. Deterministic rendering, no AI text generation. Output is confined to the declared out path; a short preview is returned with the file path." + authorizedUseNotice
}

func (t *ReportTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"findings": {
				"type": "array",
				"items": {"type": "string"},
				"minItems": 1,
				"maxItems": 16,
				"description": "Paths to findings JSON files to merge (chain from blocktack campaign run directories or tool outputs)"
			},
			"out": {
				"type": "string",
				"description": "Output markdown file path (for example <run_dir>/report.md)"
			},
			"engagement": {
				"type": "boolean",
				"description": "Render an engagement-grade deliverable (executive summary, kill chains, remediation)"
			},
			"title": {
				"type": "string",
				"description": "Report title (default: BlockTack Assessment Report / BlockTack Engagement Report)"
			},
			"target": {
				"type": "string",
				"description": "Optional target YAML for engagement-mode authorization and scope context"
			},
			"killchains": {
				"type": "string",
				"description": "Optional killchains.json path for engagement mode (financial blast radius)"
			}
		},
		"required": ["findings", "out"]
	}`)
}

func (t *ReportTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Findings   []string `json:"findings"`
		Out        string   `json:"out"`
		Engagement bool     `json:"engagement"`
		Title      string   `json:"title"`
		Target     string   `json:"target"`
		Killchains string   `json:"killchains"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if len(input.Findings) == 0 {
		return errorResult("findings is required (at least one file)"), nil
	}
	if len(input.Findings) > 16 {
		return errorResult("findings accepts at most 16 files"), nil
	}
	for _, f := range input.Findings {
		if err := validateInputFile(f, "findings entry"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if err := validateOutputFile(input.Out, "out"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Title, "title"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Target != "" {
		if err := validateInputFile(input.Target, "target"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.Killchains != "" {
		if err := validateInputFile(input.Killchains, "killchains"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	args := []string{"report", "--findings", strings.Join(input.Findings, ","), "--out", input.Out}
	if input.Engagement {
		args = append(args, "--engagement")
	}
	if input.Title != "" {
		args = append(args, "--title", input.Title)
	}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Killchains != "" {
		args = append(args, "--killchains", input.Killchains)
	}

	result, err := runCLI(ctx, t.exec, args...)
	if err != nil {
		if guardrailRefusal(result, err) {
			return refusalResult(result), nil
		}
		return failureResult("blocktack report", result, err), nil
	}

	var sb strings.Builder
	sb.WriteString("## BlockTack Report\n\n")
	fmt.Fprintf(&sb, "- **Output:** `%s`\n", input.Out)
	if input.Engagement {
		sb.WriteString("- **Mode:** engagement deliverable (executive summary, kill chains, remediation)\n")
	}
	if stderr := strings.TrimSpace(string(result.Stderr)); stderr != "" {
		fmt.Fprintf(&sb, "- **CLI:** %s\n", firstLine(stderr))
	}
	if data, readErr := os.ReadFile(input.Out); readErr == nil {
		text := strings.TrimSpace(string(data))
		if len(text) > 0 {
			preview := text
			if len(preview) > maxReportPreview {
				preview = preview[:maxReportPreview] + "\n...[truncated]"
			}
			sb.WriteString("\n### Preview\n\n```markdown\n" + preview + "\n```\n")
		}
	}
	return textResult(sb.String()), nil
}

// firstLine returns the first line of s.
func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}
