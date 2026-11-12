package barzakh

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

// serverBinary is the allowlist name of the Barzakh scanner server daemon
// (barzakh-scanner-rs crates/barzakh-server).
const serverBinary = "barzakh-server"

// ServerStartTool starts the Barzakh scanner server (barzakh-server) as a
// managed background process via the BackgroundManager, which enforces the
// same binary allowlist and argument validation as the regular executor.
type ServerStartTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStart constructs the barzakh_server_start tool.
func NewServerStart(mgr *executor.BackgroundManager) *ServerStartTool {
	return &ServerStartTool{mgr: mgr}
}

func (t *ServerStartTool) Name() string { return "barzakh_server_start" }

func (t *ServerStartTool) Description() string {
	return "Start the Barzakh scanner server (barzakh-server) as a managed background process: a REST API and web dashboard (default http://127.0.0.1:8420) backed by a SQLite scan-history database under data_dir, with X-API-Key authentication on every /api endpoint. The api_key param is passed via --api-key; when omitted the binary reads the BARZAKH_API_KEY environment variable instead, and without either the server refuses to start (this tool never passes --insecure-dev). API file reads are constrained to the scan root (--scan-root, default <data_dir>/payloads). Wraps Barzakh (firmware security scanning); authorized lab use only. The daemon runs until barzakh_server_stop is called; startup failures (missing API key, unwritable database) are written to the stderr log, so use barzakh_server_status to check whether it survived startup."
}

func (t *ServerStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"data_dir": {
				"type": "string",
				"description": "Required directory for server state; created with 0700 if missing. The SQLite database (barzakh-server-<id>.db) and the payloads directory (payload images the API can scan) are written here, with stdout/stderr logs alongside"
			},
			"bind": {
				"type": "string",
				"description": "IP address for the --bind flag (default: 127.0.0.1). The dashboard and REST API listen here"
			},
			"port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535,
				"description": "TCP port for the --port flag (default: 8420)"
			},
			"api_key": {
				"type": "string",
				"description": "API key passed via --api-key and required by every /api endpoint via the X-API-Key or Authorization: Bearer header. When omitted the binary reads the BARZAKH_API_KEY environment variable; without either the server refuses to start"
			},
			"scan_root": {
				"type": "string",
				"description": "Path to an existing directory of firmware images the API may scan (--scan-root; default: <data_dir>/payloads). API file reads are rejected outside the scan root"
			}
		},
		"required": ["data_dir"]
	}`)
}

func (t *ServerStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		DataDir  string `json:"data_dir"`
		Bind     string `json:"bind"`
		Port     *int   `json:"port"`
		APIKey   string `json:"api_key"`
		ScanRoot string `json:"scan_root"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateServerDir(input.DataDir, "data_dir"); err != nil {
		return errorResult(err.Error()), nil
	}
	bind := "127.0.0.1"
	if input.Bind != "" {
		if net.ParseIP(input.Bind) == nil {
			return errorResult(fmt.Sprintf("bind must be an IP address (e.g. 127.0.0.1), got: %s", input.Bind)), nil
		}
		bind = input.Bind
	}
	port := 8420
	if input.Port != nil {
		if *input.Port < 1 || *input.Port > 65535 {
			return errorResult("port must be 1-65535"), nil
		}
		port = *input.Port
	}
	if err := validateSafeString(input.APIKey, "api_key"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.ScanRoot != "" {
		if err := validateServerInputDir(input.ScanRoot, "scan_root"); err != nil {
			return errorResult(err.Error()), nil
		}
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := serverRandomSuffix()
	dbPath := filepath.Join(input.DataDir, "barzakh-server-"+suffix+".db")
	payloadsDir := filepath.Join(input.DataDir, "payloads")
	stdoutPath := filepath.Join(input.DataDir, "barzakh-server-"+suffix+".log")
	stderrPath := filepath.Join(input.DataDir, "barzakh-server-"+suffix+".err")

	// barzakh-server canonicalizes its scan roots and refuses to start when
	// they are missing, and its default is a CWD-relative "payloads". Always
	// pass an explicit scan root: the caller's, or the payloads directory
	// this tool manages under data_dir.
	scanRoot := input.ScanRoot
	if scanRoot == "" {
		scanRoot = payloadsDir
		if err := os.MkdirAll(payloadsDir, 0o700); err != nil {
			return errorResult(fmt.Sprintf("cannot create payloads directory %s: %v", payloadsDir, err)), nil
		}
	}

	args := []string{
		"--db", dbPath,
		"--payloads-dir", payloadsDir,
		"--scan-root", scanRoot,
		"--bind", bind,
		"--port", strconv.Itoa(port),
	}
	if input.APIKey != "" {
		args = append(args, "--api-key", input.APIKey)
	}

	proc, err := t.mgr.Start(ctx, serverBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + serverBinary + ": " + err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## Barzakh Scanner Server Started\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for stop/status chaining.
	serverJSON, _ := json.Marshal(map[string]any{
		"process_id":  proc.ID,
		"pid":         proc.PID,
		"binary":      serverBinary,
		"stdout_path": stdoutPath,
		"stderr_path": stderrPath,
		"db_path":     dbPath,
		"url":         "http://" + net.JoinHostPort(bind, strconv.Itoa(port)),
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", serverJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", serverBinary)
	echoArgs := append([]string{}, args...)
	for i, a := range echoArgs {
		if a == "--api-key" && i+1 < len(echoArgs) {
			echoArgs[i+1] = "<redacted>"
		}
	}
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", serverBinary, strings.Join(echoArgs, " "))
	fmt.Fprintf(&sb, "- **Dashboard / REST API:** http://%s\n", net.JoinHostPort(bind, strconv.Itoa(port)))
	fmt.Fprintf(&sb, "- **SQLite database:** %s\n", dbPath)
	fmt.Fprintf(&sb, "- **Payloads / scan root:** %s\n", scanRoot)
	fmt.Fprintf(&sb, "- **Server log (stdout):** %s\n", stdoutPath)
	fmt.Fprintf(&sb, "- **Server log (stderr):** %s\n", stderrPath)
	if input.APIKey != "" {
		sb.WriteString("- **Authentication:** X-API-Key (or Authorization: Bearer) required on every /api endpoint\n")
	} else {
		sb.WriteString("- **Authentication:** BARZAKH_API_KEY environment variable (the server refuses to start without an API key)\n")
	}
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `barzakh_server_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `barzakh_server_status` with process_id `%s` reports live state\n", proc.ID)
	sb.WriteString("- API file reads are rejected outside the scan root; place firmware images there before scanning.\n")
	sb.WriteString("- If the server exits immediately, its stderr log (start failure reason) explains why.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// ServerStopTool stops a scanner server previously started with
// barzakh_server_start.
type ServerStopTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStop constructs the barzakh_server_stop tool.
func NewServerStop(mgr *executor.BackgroundManager) *ServerStopTool {
	return &ServerStopTool{mgr: mgr}
}

func (t *ServerStopTool) Name() string { return "barzakh_server_stop" }

func (t *ServerStopTool) Description() string {
	return "Stop a Barzakh scanner server started with barzakh_server_start (SIGTERM to its process group, SIGKILL after 5 seconds). Wraps Barzakh (firmware security scanning); authorized lab use only. Stopping an unknown process ID is an error; stopping an already-exited server is a no-op."
}

func (t *ServerStopTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by barzakh_server_start (e.g. proc_1a2b3c4d5e6f7a8b)"
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
	sb.WriteString("## Barzakh Scanner Server Stopped\n\n")
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", input.ProcessID)
	sb.WriteString("- The server's process group received SIGTERM (SIGKILL after 5 seconds if needed).\n")
	fmt.Fprintf(&sb, "- Use `barzakh_server_status` with process_id `%s` to confirm the final state.\n", input.ProcessID)

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// ServerStatusTool reports the live state of scanner servers started via
// barzakh_server_start: one process by ID, or every managed barzakh-server
// process when no ID is given.
type ServerStatusTool struct {
	mgr *executor.BackgroundManager
}

// NewServerStatus constructs the barzakh_server_status tool.
func NewServerStatus(mgr *executor.BackgroundManager) *ServerStatusTool {
	return &ServerStatusTool{mgr: mgr}
}

func (t *ServerStatusTool) Name() string { return "barzakh_server_status" }

func (t *ServerStatusTool) Description() string {
	return "Report the state of Barzakh scanner servers started with barzakh_server_start: running flag, PID, uptime, exit code, output truncation, and database/log file paths. With no process_id, every managed barzakh-server process is listed. Wraps Barzakh (firmware security scanning); authorized lab use only. Read-only query."
}

func (t *ServerStatusTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"process_id": {
				"type": "string",
				"description": "Process ID returned by barzakh_server_start. Omit to list all managed barzakh-server processes"
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
			Content: []mcp.ContentBlock{{Type: "text", Text: renderServerStatuses("Barzakh Scanner Server Status", "No managed barzakh-server processes.", []executor.BackgroundStatus{*status})}},
		}, nil
	}

	filtered := make([]executor.BackgroundStatus, 0)
	for _, st := range t.mgr.List() {
		if st.Binary == serverBinary {
			filtered = append(filtered, st)
		}
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: renderServerStatuses("Managed Barzakh Scanner Servers", "No managed barzakh-server processes.", filtered)}},
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
// is used for the scanner server state directory.
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

// validateServerInputDir ensures a directory the wrapped CLI will scan
// actually exists (barzakh-server canonicalizes scan roots and refuses to
// start when one is missing).
func validateServerInputDir(dir, field string) error {
	if dir == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validateSafeString(dir, field); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory, not a file: %s", field, dir)
	}
	return nil
}
