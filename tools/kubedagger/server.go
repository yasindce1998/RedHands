package kubedagger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// serverBinary is the allowlist name of the KubeDagger C2 server daemon
// (KubeDagger cmd/kubedagger-server).
const serverBinary = "kubedagger-server"

// maxServerRateLimit bounds the -rate-limit flag (requests per second per
// IP) exposed by kubedagger_server_start.
const maxServerRateLimit = 100000

// ServerStartTool starts the KubeDagger C2 server (kubedagger-server) as a
// managed background process via the BackgroundManager, which enforces the
// same binary allowlist and argument validation as the regular executor.
type ServerStartTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStart constructs the kubedagger_server_start tool.
func NewServerStart(mgr *executor.BackgroundManager) *ServerStartTool {
	return &ServerStartTool{mgr: mgr}
}

func (t *ServerStartTool) Name() string { return "kubedagger_server_start" }

func (t *ServerStartTool) Description() string {
	return "Start the KubeDagger C2 server (kubedagger-server) as a managed background process: an HTTP/2 mTLS agent listener on the binary default 0.0.0.0:443 with structured JSONL event telemetry (--events is generated under events_dir and enables report generation and web UI campaign views), optional scope policy YAML (--scope: allowed namespaces/domains/CIDRs; tasks outside scope are rejected), optional malleable C2 profile (--malleable: beacon sleep/jitter/User-Agent), optional campaign web UI (--webui address, e.g. 127.0.0.1:8080), per-IP rate limiting (--rate-limit requests/second), and agent pre-shared key (--psk, X-Api-Key auth). HIGH IMPACT: starts a live command-and-control (C2) server for authorized lab use only (KubeDagger Kubernetes adversary emulation); it requires the kubedagger-server binary on the executor allowlist and is approval-gated. The daemon runs until kubedagger_server_stop is called; startup failures (bad scope/malleable YAML, port conflicts) are written to the stderr log, so use kubedagger_server_status to check whether it survived startup."
}

func (t *ServerStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"events_dir": {
				"type": "string",
				"description": "Required directory for server output files; created with 0700 if missing. The JSONL event log (--events) is written to kubedagger-server-<id>.events.jsonl here, with stdout/stderr logs alongside"
			},
			"scope": {
				"type": "string",
				"description": "Path to an existing scope policy YAML (allowed namespaces/domains/CIDRs; tasks outside scope are rejected)"
			},
			"malleable": {
				"type": "string",
				"description": "Path to an existing malleable C2 profile YAML (beacon sleep/jitter/User-Agent)"
			},
			"webui": {
				"type": "string",
				"description": "Address for the campaign web UI (timeline + replay), e.g. 127.0.0.1:8080; empty = disabled. Non-loopback listeners require web UI TLS certificates configured on the server side; the KUBEDAGGER_WEBUI_TOKEN env var sets the UI auth token"
			},
			"rate_limit": {
				"type": "number",
				"exclusiveMinimum": 0,
				"maximum": 100000,
				"description": "Requests per second per IP for the --rate-limit flag (agent listener throttling)"
			},
			"psk": {
				"type": "string",
				"description": "Pre-shared key for agent auth (X-Api-Key) passed via --psk; agents must present it to the C2 listener"
			}
		},
		"required": ["events_dir"]
	}`)
}

func (t *ServerStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		EventsDir string   `json:"events_dir"`
		Scope     string   `json:"scope"`
		Malleable string   `json:"malleable"`
		WebUI     string   `json:"webui"`
		RateLimit *float64 `json:"rate_limit"`
		PSK       string   `json:"psk"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateServerDir(input.EventsDir, "events_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Scope != "" {
		if err := validateServerInputFile(input.Scope, "scope"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.Malleable != "" {
		if err := validateServerInputFile(input.Malleable, "malleable"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.WebUI != "" {
		if err := validateServerHostPort(input.WebUI, "webui"); err != nil {
			return errorResult(err.Error()), nil
		}
	}
	if input.RateLimit != nil {
		if *input.RateLimit <= 0 || *input.RateLimit > maxServerRateLimit {
			return errorResult(fmt.Sprintf("rate_limit must be greater than 0 and at most %d requests per second", maxServerRateLimit)), nil
		}
	}
	if err := validateSafeString(input.PSK, "psk"); err != nil {
		return errorResult(err.Error()), nil
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := serverRandomSuffix()
	eventsPath := filepath.Join(input.EventsDir, "kubedagger-server-"+suffix+".events.jsonl")
	stdoutPath := filepath.Join(input.EventsDir, "kubedagger-server-"+suffix+".log")
	stderrPath := filepath.Join(input.EventsDir, "kubedagger-server-"+suffix+".err")

	args := []string{"--events", eventsPath}
	if input.Scope != "" {
		args = append(args, "--scope", input.Scope)
	}
	if input.Malleable != "" {
		args = append(args, "--malleable", input.Malleable)
	}
	if input.WebUI != "" {
		args = append(args, "--webui", input.WebUI)
	}
	if input.RateLimit != nil {
		args = append(args, "--rate-limit", strconv.FormatFloat(*input.RateLimit, 'f', -1, 64))
	}
	if input.PSK != "" {
		args = append(args, "--psk", input.PSK)
	}

	proc, err := t.mgr.Start(ctx, serverBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + serverBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## KubeDagger C2 Server Started\n\n")
	sb.WriteString("HIGH IMPACT: this is a live C2 server for authorized lab use only.\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for stop/status chaining and
	// ${step_id.json.events_path} for report generation.
	serverJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      serverBinary,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
		"events_path": eventsPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", serverJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", serverBinary)
	// The PSK is redacted here; it is still part of the recorded argv.
	echoArgs := append([]string{}, args...)
	for i, a := range echoArgs {
		if a == "--psk" && i+1 < len(echoArgs) {
			echoArgs[i+1] = "<redacted>"
		}
	}
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", serverBinary, strings.Join(echoArgs, " "))
	fmt.Fprintf(&sb, "- **Agent listener:** HTTP/2 mTLS on the binary default 0.0.0.0:443\n")
	if input.WebUI != "" {
		fmt.Fprintf(&sb, "- **Campaign web UI:** http://%s (requires KUBEDAGGER_WEBUI_TOKEN)\n", input.WebUI)
	}
	fmt.Fprintf(&sb, "- **Event telemetry (JSONL):** %s\n", eventsPath)
	fmt.Fprintf(&sb, "- **Server log (stdout):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Server log (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `kubedagger_server_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `kubedagger_server_status` with process_id `%s` reports live state\n", proc.ID)
	fmt.Fprintf(&sb, "- `kubedagger_report` can consume the events file `%s` once agents have checked in\n", eventsPath)
	sb.WriteString("- If the server exits immediately, its stderr log (start failure reason) explains why.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// ServerStopTool stops a C2 server previously started with
// kubedagger_server_start.
type ServerStopTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStop constructs the kubedagger_server_stop tool.
func NewServerStop(mgr *executor.BackgroundManager) *ServerStopTool {
	return &ServerStopTool{mgr: mgr}
}

func (t *ServerStopTool) Name() string { return "kubedagger_server_stop" }

func (t *ServerStopTool) Description() string {
	return "Stop a KubeDagger C2 server started with kubedagger_server_start (SIGTERM to its process group, SIGKILL after 5 seconds). HIGH IMPACT toolset: KubeDagger is Kubernetes adversary emulation for authorized lab use only; this tool is approval-gated. Stopping an unknown process ID is an error; stopping an already-exited server is a no-op."
}

func (t *ServerStopTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by kubedagger_server_start (e.g. proc_1a2b3c4d5e6f7a8b)"
			}
		},
		"required": ["process_id"]
	}`)
}

func (t *ServerStopTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if input.ProcessID == "" {
		return errorResult("process_id is required"), nil
	}
	if err := validateSafeString(input.ProcessID, "process_id"); err != nil {
		return errorResult(err.Error()), nil
	}

	if err := t.mgr.Stop(input.ProcessID); err != nil {
		return errorResult(err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## KubeDagger C2 Server Stopped\n\n")
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", input.ProcessID)
	sb.WriteString("- The server's process group received SIGTERM (SIGKILL after 5 seconds if needed).\n")
	fmt.Fprintf(&sb, "- Use `kubedagger_server_status` with process_id `%s` to confirm the final state.\n", input.ProcessID)

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// ServerStatusTool reports the live state of C2 servers started via
// kubedagger_server_start: one process by ID, or every managed
// kubedagger-server process when no ID is given.
type ServerStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStatus constructs the kubedagger_server_status tool.
func NewServerStatus(mgr *executor.BackgroundManager) *ServerStatusTool {
	return &ServerStatusTool{mgr: mgr}
}

func (t *ServerStatusTool) Name() string { return "kubedagger_server_status" }

func (t *ServerStatusTool) Description() string {
	return "Report the state of KubeDagger C2 servers started with kubedagger_server_start: running flag, PID, uptime, exit code, output truncation, and event/log file paths. With no process_id, every managed kubedagger-server process is listed. HIGH IMPACT toolset: KubeDagger is Kubernetes adversary emulation for authorized lab use only; this tool is approval-gated. Read-only query."
}

func (t *ServerStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by kubedagger_server_start. Omit to list all managed kubedagger-server processes"
			}
		}
	}`)
}

func (t *ServerStatusTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		ProcessID string `json:"process_id"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if input.ProcessID != "" {
		if err := validateSafeString(input.ProcessID, "process_id"); err != nil {
			return errorResult(err.Error()), nil
		}
		status, err := t.mgr.Status(input.ProcessID)
		if err != nil {
			return errorResult(err.Error()), nil
		}
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: renderServerStatuses("KubeDagger C2 Server Status", "No managed kubedagger-server processes.", []executor.BackgroundStatus{*status})}},
		}, nil
	}

	filtered := make([]executor.BackgroundStatus, 0)
	for _, st := range t.mgr.List() {
		if st.Binary == serverBinary {
			filtered = append(filtered, st)
		}
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderServerStatuses("Managed KubeDagger C2 Servers", "No managed kubedagger-server processes.", filtered)}},
	}, nil
}

// renderServerStatuses renders one or more background process states as
// markdown.
func renderServerStatuses(title, emptyMessage string, statuses []executor.BackgroundStatus) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n\n", title)
	if len(statuses) == 0 {
		sb.WriteString(emptyMessage + "\n")
		return sb.String()
	}
	for _, st := range statuses {
		fmt.Fprintf(&sb, "### %s (%s)\n\n", st.ID, st.Binary)
		if st.Running {
			sb.WriteString("- **Running:** yes\n")
		} else {
			sb.WriteString("- **Running:** no\n")
		}
		fmt.Fprintf(&sb, "- **PID:** %d\n", st.PID)
		fmt.Fprintf(&sb, "- **Started:** %s\n", st.StartedAt.Format(time.RFC3339))
		if st.Running {
			fmt.Fprintf(&sb, "- **Uptime:** %s\n", time.Since(st.StartedAt).Round(time.Second))
		} else if !st.EndedAt.IsZero() {
			fmt.Fprintf(&sb, "- **Ended:** %s (ran %s)\n", st.EndedAt.Format(time.RFC3339), st.EndedAt.Sub(st.StartedAt).Round(time.Second))
			fmt.Fprintf(&sb, "- **Exit code:** %d\n", st.ExitCode)
		}
		if len(st.Args) > 0 {
			fmt.Fprintf(&sb, "- **Command:** %s %s\n", st.Binary, strings.Join(st.Args, " "))
		}
		if st.StdoutPath != "" {
			fmt.Fprintf(&sb, "- **Server log (stdout):** %s\n", st.StdoutPath)
		}
		if st.StderrPath != "" {
			fmt.Fprintf(&sb, "- **Server log (stderr):** %s\n", st.StderrPath)
		}
		if st.StdoutTruncated {
			sb.WriteString("- **Stdout truncated:** yes (256 MiB cap reached; further output dropped)\n")
		}
		if st.StderrTruncated {
			sb.WriteString("- **Stderr truncated:** yes (256 MiB cap reached; further output dropped)\n")
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// serverRandomSuffix returns 8 hex chars used to name per-process output
// files. It is generated before Start because Start requires the output
// paths up front.
func serverRandomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// validateServerDir enforces a non-empty metachar-free directory path and
// ensures it exists, creating it (and parents) with 0700 when missing. It
// is used for the C2 server output directory.
func validateServerDir(dir, field string) error {
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

// validateServerInputFile ensures a path the wrapped CLI will read actually
// exists and is a regular file (kubedagger-server fatals on unloadable
// scope/malleable YAML).
func validateServerInputFile(path, field string) error {
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

// validateServerHostPort checks that s is a "host:port" listener address.
func validateServerHostPort(s, field string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%s must be a host:port address (e.g. 127.0.0.1:8080): %v", field, err)
	}
	if host == "" {
		return fmt.Errorf("%s host is required", field)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port in %s: %s", field, port)
	}
	return nil
}
