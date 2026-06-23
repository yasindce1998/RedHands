package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type HTTPProbeInput struct {
	Targets      string `json:"targets"`
	Ports        string `json:"ports,omitempty"`
	StatusCode   bool   `json:"status_code,omitempty"`
	Title        bool   `json:"title,omitempty"`
	TechDetect   bool   `json:"tech_detect,omitempty"`
	FollowRedir  bool   `json:"follow_redirects,omitempty"`
	Threads      int    `json:"threads,omitempty"`
	CDN          bool   `json:"cdn,omitempty"`
	Hash         string `json:"hash,omitempty"`
	JARM         bool   `json:"jarm,omitempty"`
	ResponseBody bool   `json:"response_body,omitempty"`
	ContentLen   bool   `json:"content_length,omitempty"`
	Method       string `json:"method,omitempty"`
	MatchCodes   string `json:"match_codes,omitempty"`
	FilterCodes  string `json:"filter_codes,omitempty"`
	JSONOutput   bool   `json:"json_output,omitempty"`
	WebServer    bool   `json:"web_server,omitempty"`
	IP           bool   `json:"ip,omitempty"`
	CNAME        bool   `json:"cname,omitempty"`
	ExtractRegex string `json:"extract_regex,omitempty"`
	ProbeAllIPs  bool   `json:"probe_all_ips,omitempty"`
}

type HTTPProbeTool struct {
	exec executor.Executor
}

func NewHTTPProbe(exec executor.Executor) *HTTPProbeTool {
	return &HTTPProbeTool{exec: exec}
}

func (t *HTTPProbeTool) Name() string { return "httpx_probe" }

func (t *HTTPProbeTool) Description() string {
	return "Probe HTTP services on targets to detect live web servers, extract titles, status codes, technologies, CDN detection, JARM fingerprints, and more."
}

func (t *HTTPProbeTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"targets": {
				"type": "string",
				"description": "Comma-separated list of targets (IPs, domains, or URLs) to probe"
			},
			"ports": {
				"type": "string",
				"description": "Ports to probe (e.g., '80,443,8080,8443')"
			},
			"status_code": {
				"type": "boolean",
				"description": "Include HTTP status code in output"
			},
			"title": {
				"type": "boolean",
				"description": "Include page title in output"
			},
			"tech_detect": {
				"type": "boolean",
				"description": "Enable technology detection (Wappalyzer-like)"
			},
			"follow_redirects": {
				"type": "boolean",
				"description": "Follow HTTP redirects"
			},
			"threads": {
				"type": "integer",
				"description": "Number of concurrent threads (default: 50)"
			},
			"cdn": {
				"type": "boolean",
				"description": "Detect CDN/WAF in use"
			},
			"hash": {
				"type": "string",
				"description": "Hash algorithm to use for response body (md5, sha256, etc.)"
			},
			"jarm": {
				"type": "boolean",
				"description": "Enable JARM TLS fingerprinting"
			},
			"response_body": {
				"type": "boolean",
				"description": "Include response body in output"
			},
			"content_length": {
				"type": "boolean",
				"description": "Include content length in output"
			},
			"method": {
				"type": "string",
				"enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
				"description": "HTTP method to use for probing"
			},
			"match_codes": {
				"type": "string",
				"description": "Match only these status codes (e.g., '200,301,302')"
			},
			"filter_codes": {
				"type": "string",
				"description": "Filter/exclude these status codes (e.g., '404,500')"
			},
			"json_output": {
				"type": "boolean",
				"description": "Output results in JSON format"
			},
			"web_server": {
				"type": "boolean",
				"description": "Include web server name in output"
			},
			"ip": {
				"type": "boolean",
				"description": "Include resolved IP address in output"
			},
			"cname": {
				"type": "boolean",
				"description": "Include CNAME record in output"
			},
			"extract_regex": {
				"type": "string",
				"description": "Regex pattern to extract from response body"
			},
			"probe_all_ips": {
				"type": "boolean",
				"description": "Probe all IPs associated with a domain"
			}
		},
		"required": ["targets"]
	}`)
}

func (t *HTTPProbeTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input HTTPProbeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateTargets(input.Targets); err != nil {
		return errorResult(err.Error()), nil
	}

	targets := strings.Split(input.Targets, ",")
	args := []string{"-silent"}

	if input.Ports != "" {
		args = append(args, "-ports", input.Ports)
	}
	if input.StatusCode {
		args = append(args, "-status-code")
	}
	if input.Title {
		args = append(args, "-title")
	}
	if input.TechDetect {
		args = append(args, "-tech-detect")
	}
	if input.FollowRedir {
		args = append(args, "-follow-redirects")
	}
	if input.Threads > 0 {
		args = append(args, "-threads", fmt.Sprintf("%d", input.Threads))
	}
	if input.CDN {
		args = append(args, "-cdn")
	}
	if input.Hash != "" {
		args = append(args, "-hash", input.Hash)
	}
	if input.JARM {
		args = append(args, "-jarm")
	}
	if input.ResponseBody {
		args = append(args, "-include-response")
	}
	if input.ContentLen {
		args = append(args, "-content-length")
	}
	if input.Method != "" {
		args = append(args, "-x", input.Method)
	}
	if input.MatchCodes != "" {
		args = append(args, "-mc", input.MatchCodes)
	}
	if input.FilterCodes != "" {
		args = append(args, "-fc", input.FilterCodes)
	}
	if input.JSONOutput {
		args = append(args, "-json")
	}
	if input.WebServer {
		args = append(args, "-web-server")
	}
	if input.IP {
		args = append(args, "-ip")
	}
	if input.CNAME {
		args = append(args, "-cname")
	}
	if input.ExtractRegex != "" {
		args = append(args, "-extract-regex", input.ExtractRegex)
	}
	if input.ProbeAllIPs {
		args = append(args, "-probe-all-ips")
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target != "" {
			args = append(args, "-u", target)
		}
	}

	result, err := t.exec.Run(ctx, "httpx", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("httpx execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	lines := strings.Split(output, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "## HTTP Probe Results\n\nProbed %d target(s), %d responded:\n\n", len(targets), len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Fprintf(&sb, "- %s\n", line)
		}
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

func validateTargets(targets string) error {
	if targets == "" {
		return fmt.Errorf("targets is required")
	}
	forbidden := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\"}
	for _, c := range forbidden {
		if strings.Contains(targets, c) {
			return fmt.Errorf("targets contains forbidden character: %q", c)
		}
	}
	return nil
}
