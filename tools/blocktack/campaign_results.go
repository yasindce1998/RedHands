package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// maxReportPreview bounds the markdown report preview echoed by
// blocktack_report (the full report stays in the output file).
const maxReportPreview = 4096

// CampaignResultsTool reads a finished (or stopped) campaign's run
// directory: findings.json, killchains.json, and status.json. Read-only;
// paths are confined to the declared run directory.
type CampaignResultsTool struct{}

// NewCampaignResults constructs the blocktack_campaign_results tool.
func NewCampaignResults() *CampaignResultsTool {
	return &CampaignResultsTool{}
}

func (t *CampaignResultsTool) Name() string { return "blocktack_campaign_results" }

func (t *CampaignResultsTool) Description() string {
	return "Fetch the results of a BlockTack campaign run directory: the findings JSON array (fenced, with severity summary, chainable via ${step_id.json...} and recordable by campaign rules), killchains.json with financial blast radius when present, and the status.json snapshot (state, steps, findings so far — the only machine-readable state for stopped mid-run campaigns). Read-only file access inside the run directory. Use blocktack_campaign_status first to locate the run dir of a given process_id; findings.json exists only for runs that completed." + authorizedUseNotice
}

func (t *CampaignResultsTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"run_dir": {
				"type": "string",
				"description": "Campaign run directory (the timestamped subdirectory under the out_dir passed to blocktack_campaign_start; see blocktack_campaign_status)"
			},
			"include_log": {
				"type": "boolean",
				"description": "Include a tail of campaign.log (the human-readable run log) in the output"
			}
		},
		"required": ["run_dir"]
	}`)
}

func (t *CampaignResultsTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		RunDir     string `json:"run_dir"`
		IncludeLog bool   `json:"include_log"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateSafeString(input.RunDir, "run_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.RunDir == "" {
		return errorResult("run_dir is required"), nil
	}
	info, err := os.Stat(input.RunDir)
	if err != nil {
		return errorResult(fmt.Sprintf("run_dir not accessible: %v", err)), nil
	}
	if !info.IsDir() {
		return errorResult("run_dir must be a directory"), nil
	}

	var sb strings.Builder
	sb.WriteString("## BlockTack Campaign Results\n\n")
	fmt.Fprintf(&sb, "- **Run dir:** %s\n", input.RunDir)

	// status.json: always useful (crash-resilient), especially for
	// stopped runs.
	if snap := readStatusSnapshot(input.RunDir); snap != "" {
		sb.WriteString("\n### status.json\n\n```json\n" + snap + "\n```\n")
	} else {
		sb.WriteString("\n- **status.json:** absent (the run was stopped before its first step completed)\n")
	}

	// killchains.json: optional, only when chains were found.
	killchains := ""
	if data, err := os.ReadFile(filepath.Join(input.RunDir, "killchains.json")); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		killchains = strings.TrimSpace(string(data))
	}
	if killchains != "" {
		sb.WriteString("\n### killchains.json\n\n```json\n" + killchains + "\n```\n")
	}

	// findings.json: only written when the run completes.
	findingsPath := filepath.Join(input.RunDir, "findings.json")
	if data, err := os.ReadFile(findingsPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		sb.WriteString("\n### findings.json\n\n")
		sb.WriteString(findingsSummary(data) + "\n\n")
		payload := json.RawMessage(strings.TrimSpace(string(data)))
		sb.WriteString("```json\n" + string(payload) + "\n```\n")
		// Structured findings for record rules and dot-path chaining.
		return &mcp.ToolResult{
			Content:           []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
			StructuredContent: payload,
		}, nil
	}
	sb.WriteString("\n- **findings.json:** absent (the campaign has not completed; poll blocktack_campaign_status)\n")

	if input.IncludeLog {
		if data, err := os.ReadFile(filepath.Join(input.RunDir, "campaign.log")); err == nil {
			tail := tailString(string(data), maxReportPreview)
			if tail != "" {
				sb.WriteString("\n### campaign.log (tail)\n\n```\n" + tail + "\n```\n")
			}
		}
	}
	return textResult(sb.String()), nil
}

// tailString returns the last at-most-n bytes of s, cut to a line start.
func tailString(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	tail := s[len(s)-n:]
	if idx := strings.IndexByte(tail, '\n'); idx >= 0 {
		tail = tail[idx+1:]
	}
	return tail
}
