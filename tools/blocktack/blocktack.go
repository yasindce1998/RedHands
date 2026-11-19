// Package blocktack wraps the BlockTack adversary-simulation platform for
// blockchain systems (https://github.com/yasindce1998/BlockTack): one Go
// CLI plus Rust engines that cover recon, contract analysis, node audits,
// in-memory exploit simulation, and playbook-driven campaigns.
//
// Safety model: BlockTack enforces its own guardrails in code — every
// command refuses targets whose YAML lacks an unexpired authorization
// block, and safe mode (the only mode these wrappers ever invoke) confines
// endpoints to loopback or authorization.liveTargets. Guardrail refusals
// exit with code 3, which these wrappers report as a distinct refusal
// instead of an operational failure. The --unsafe flag is deliberately
// never passed or exposed.
package blocktack

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

const (
	// blocktackBinary is the allowlist name of the BlockTack CLI.
	blocktackBinary = "blocktack"
	// evmEngineBinary and solanaEngineBinary are the allowlist names of
	// the Rust engines (stdin JSON job → stdout findings JSON).
	evmEngineBinary     = "blocktack-evm"
	solanaEngineBinary  = "blocktack-solana"
	defaultInstallRoot  = "/opt/blocktack"
	authorizedUseNotice = " Wraps BlockTack (blockchain adversary simulation); authorized assessments only."
)

// installRoot returns the BlockTack release tree that BLOCKTACK_ROOT is
// set to for every child process (taxonomy, adapters, playbooks, corpus,
// engines). scripts/install-tools.sh extracts the release there; operators
// point REDHANDS_BLOCKTACK_ROOT at an alternative (for example a source
// checkout) when needed.
func installRoot() string {
	if r := os.Getenv("REDHANDS_BLOCKTACK_ROOT"); r != "" {
		return r
	}
	return defaultInstallRoot
}

// childEnv returns the environment entries every blocktack child process
// receives: BLOCKTACK_ROOT (taxonomy, adapters, playbooks) plus
// BLOCKTACK_JSON_ERRORS=1 for structured error objects on stderr.
// BLOCKTACK_ENGINES is only set when an engines directory actually exists
// (the release layout); a source checkout leaves it unset so BlockTack
// falls back to its own engine-*/target/release resolution.
func childEnv() []string {
	root := installRoot()
	env := []string{
		"BLOCKTACK_ROOT=" + root,
		"BLOCKTACK_JSON_ERRORS=1",
	}
	engines := os.Getenv("REDHANDS_BLOCKTACK_ENGINES")
	if engines == "" {
		engines = filepath.Join(root, "engines")
	}
	if st, err := os.Stat(engines); err == nil && st.IsDir() {
		env = append(env, "BLOCKTACK_ENGINES="+engines)
	}
	return env
}

// runCLI executes the blocktack CLI with the required environment when
// the executor supports it; plain executors fall back to Run.
func runCLI(ctx context.Context, exec executor.Executor, args ...string) (*executor.Result, error) {
	return runBinary(ctx, exec, blocktackBinary, args...)
}

// runBinary executes a blocktack-family binary (CLI or engine) with the
// required environment, optionally feeding stdin.
func runBinary(ctx context.Context, exec executor.Executor, binary string, args ...string) (*executor.Result, error) {
	return runBinaryStdin(ctx, exec, nil, binary, args...)
}

// runBinaryStdin is runBinary with an optional stdin payload (used by the
// engine contract, which reads a JSON job from stdin).
func runBinaryStdin(ctx context.Context, exec executor.Executor, stdin []byte, binary string, args ...string) (*executor.Result, error) {
	opts := executor.RunOptions{Env: childEnv(), Stdin: stdin}
	if ee, ok := exec.(executor.EnvExecutor); ok {
		return ee.RunEnv(ctx, opts, binary, args...)
	}
	return exec.Run(ctx, binary, args...)
}

// guardrailRefusal reports whether an execution result is a BlockTack
// guardrail refusal (exit code 3): an unauthorized, expired, or
// non-loopback/unlisted target. Distinct from operational failures.
func guardrailRefusal(result *executor.Result, err error) bool {
	return err != nil && result != nil && result.ExitCode == 3
}

// refusalResult renders a guardrail refusal as a tool error, preferring
// the structured error object BlockTack prints on stderr
// ({"error":{"code","message",...}}) when it parses.
func refusalResult(result *executor.Result) *mcp.ToolResult {
	if result != nil && len(result.Stderr) > 0 {
		var obj struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
				Target  string `json:"target"`
			} `json:"error"`
		}
		if err := json.Unmarshal(result.Stderr, &obj); err == nil && obj.Error.Message != "" {
			detail := fmt.Sprintf("BlockTack guardrail refusal (%s): %s", obj.Error.Code, obj.Error.Message)
			if obj.Error.Target != "" {
				detail += " [target: " + obj.Error.Target + "]"
			}
			detail += ". The target YAML needs an unexpired authorization block, and every endpoint must be loopback or listed in authorization.liveTargets."
			return errorResult(detail)
		}
	}
	return errorResult("BlockTack refused the target (guardrail exit 3): authorization missing/expired or a non-loopback endpoint not listed in authorization.liveTargets")
}

// failureResult renders an operational failure with the CLI's stderr.
func failureResult(stage string, result *executor.Result, err error) *mcp.ToolResult {
	stderr := ""
	if result != nil {
		stderr = strings.TrimSpace(string(result.Stderr))
	}
	msg := fmt.Sprintf("%s failed: %s", stage, err.Error())
	if stderr != "" {
		msg += "\n" + stderr
	}
	return errorResult(msg)
}

// ---------------------------------------------------------------------------
// Input validation (mirrors the telecom toolset conventions).
// ---------------------------------------------------------------------------

var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

const maxSafeStringLen = 4096

func validateSafeString(s, field string) error {
	if s == "" {
		return nil
	}
	if len(s) > maxSafeStringLen {
		return fmt.Errorf("%s too long (max %d chars)", field, maxSafeStringLen)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validateInputFile ensures a path the wrapped CLI will read exists and is
// a regular file.
func validateInputFile(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(path, field); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file, not a directory", field)
	}
	return nil
}

// validateOutputFile ensures a path the wrapped CLI will write is safe and
// lives in an existing (or creatable) directory.
func validateOutputFile(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(path, field); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("directory for %s not accessible: %v", field, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("parent of %s is not a directory: %s", field, dir)
	}
	return nil
}

// validateOutputDir enforces a non-empty metachar-free directory path and
// ensures it exists, creating it (and parents) with 0700 when missing.
func validateOutputDir(dir, field string) error {
	if dir == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(dir, field); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is a file, not a directory: %s", field, dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot access %s %s: %v", field, dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create %s %s: %v", field, dir, err)
	}
	return nil
}

// isLocalHostname mirrors BlockTack's hostIsLocal classification
// (internal/core/target.go): loopback literals, localhost, and the
// Docker Desktop host gateway. Anything else is a live target.
func isLocalHostname(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "host.docker.internal") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateLoopbackURL enforces the engine-call safety contract: the
// engines do not run BlockTack's safe-mode check themselves, so this
// wrapper confines direct engine calls to loopback endpoints. Live
// targets must go through a campaign with a target file carrying an
// authorization block instead.
func validateLoopbackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid rpc_url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("rpc_url scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("rpc_url host is required")
	}
	if u.User != nil {
		return fmt.Errorf("rpc_url must not contain credentials")
	}
	if !isLocalHostname(u.Hostname()) {
		return fmt.Errorf("rpc_url must point at a loopback host (blocktack_engine_call never passes --unsafe); use a target file with an authorization block and blocktack_campaign_start for live targets")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Result rendering.
// ---------------------------------------------------------------------------

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func textResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
	}
}

// jsonResult renders a summary header, a fenced JSON block (the chaining
// contract: ${step_id.json...} placeholders and campaign record rules),
// and optional StructuredContent for protocol revisions that support it.
func jsonResult(header, summary string, payload json.RawMessage) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString(header + "\n\n")
	if summary != "" {
		sb.WriteString(summary + "\n\n")
	}
	sb.WriteString("```json\n")
	sb.WriteString(strings.TrimSpace(string(payload)))
	sb.WriteString("\n```\n")
	return &mcp.ToolResult{
		Content:           []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
		StructuredContent: payload,
	}
}

// findingsSummary counts findings by severity from a findings JSON array
// (BlockTack finding shape: {id,title,severity,...}).
func findingsSummary(payload []byte) string {
	var findings []struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(payload, &findings); err != nil {
		return "Findings: unavailable (unparseable output)"
	}
	if len(findings) == 0 {
		return "Findings: **0** (no findings)"
	}
	counts := map[string]int{}
	order := []string{}
	for _, f := range findings {
		if counts[f.Severity] == 0 {
			order = append(order, f.Severity)
		}
		counts[f.Severity]++
	}
	parts := make([]string, 0, len(order)+1)
	for _, sev := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
	}
	return fmt.Sprintf("Findings: **%d** (%s)", len(findings), strings.Join(parts, ", "))
}

// findingsToolResult renders the standard shape for findings-producing
// tools: header, summary, fenced JSON, StructuredContent.
func findingsToolResult(header string, stdout []byte) *mcp.ToolResult {
	payload := json.RawMessage(strings.TrimSpace(string(stdout)))
	if len(payload) == 0 {
		payload = json.RawMessage("[]")
	}
	return jsonResult(header, findingsSummary(payload), payload)
}
