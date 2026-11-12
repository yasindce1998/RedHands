package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// correlatorBinary is the allowlist name of the StaticZero protocol
// correlation daemon.
const correlatorBinary = "protocol-correlator"

// correlator defaults and bounds, verified against tools/src/
// protocol_correlator.rs: --ingest-port 7892 (loopback TCP listener for
// JSON-lines TelecomEvent ingest), --window-ms 5000, --threshold 0.7,
// --output json (json/csv/syslog on stdout) and --max-events 10000.
const (
	defaultCorrelatorIngestPort = 7892
	defaultCorrelatorWindowMS   = 5000
	defaultCorrelatorThreshold  = 0.7
	defaultCorrelatorMaxEvents  = 10000

	maxCorrelatorWindowMS  = 3600000 // 1 hour
	maxCorrelatorMaxEvents = 1000000
)

// validCorrelatorOutputFormats mirrors the output formats accepted by
// protocol-correlator's --output flag (json, csv, syslog).
var validCorrelatorOutputFormats = map[string]bool{
	"json":   true,
	"csv":    true,
	"syslog": true,
}

// CorrelatorStartTool starts the StaticZero protocol-correlator as a managed
// background process via the BackgroundManager, which enforces the same
// binary allowlist and argument validation as the regular executor.
type CorrelatorStartTool struct {
	mgr *executor.BackgroundManager
}

// NewCorrelatorStart constructs the telecom_correlator_start tool.
func NewCorrelatorStart(mgr *executor.BackgroundManager) *CorrelatorStartTool {
	return &CorrelatorStartTool{mgr: mgr}
}

func (t *CorrelatorStartTool) Name() string { return "telecom_correlator_start" }

func (t *CorrelatorStartTool) Description() string {
	return "Launch the StaticZero cross-layer protocol correlation engine (protocol-correlator) as a managed background process: listens on 127.0.0.1 (default port 7892) for JSON-lines TelecomEvent ingest (layers radio/nas/transport/signaling/core/application), correlates events within a sliding time window against rules for IMSI catchers, downgrade attacks, SS7 tracking, GTP hijack, VoLTE interception, slice escape, roaming fraud and toll fraud, and writes detected threats (CorrelatedThreat JSON) to its stdout log in the selected format (json, csv or syslog). Events are ingested by connecting TCP clients to the port — the tool only starts the engine. Wraps StaticZero (eBPF telecom security research); authorized lab use only. If the daemon exits immediately (for example the ingest port is already bound), check the stderr log via telecom_correlator_status."
}

func (t *CorrelatorStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"logs_dir": {
				"type": "string",
				"description": "Required directory for daemon output files; created with 0700 if missing. Correlated threats are written to <logs_dir>/protocol-correlator-<id>.log; diagnostics go to <logs_dir>/protocol-correlator-<id>.err"
			},
			"ingest_port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535,
				"description": "TCP port on 127.0.0.1 for JSON-lines event ingest (default 7892)"
			},
			"window_ms": {
				"type": "integer",
				"minimum": 1,
				"maximum": 3600000,
				"description": "Correlation time window in milliseconds (default 5000)"
			},
			"threshold": {
				"type": "number",
				"minimum": 0.0,
				"maximum": 1.0,
				"description": "Minimum confidence (0.0-1.0) for a correlated threat to be reported (default 0.7)"
			},
			"output_format": {
				"type": "string",
				"enum": ["json", "csv", "syslog"],
				"description": "Format of the threat output written to the stdout log (default json)"
			},
			"max_events": {
				"type": "integer",
				"minimum": 1,
				"maximum": 1000000,
				"description": "Maximum events held in the correlation window (default 10000; older events are evicted)"
			}
		},
		"required": ["logs_dir"]
	}`)
}

func (t *CorrelatorStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		LogsDir      string  `json:"logs_dir"`
		IngestPort   int64   `json:"ingest_port"`
		WindowMS     int64   `json:"window_ms"`
		Threshold    float64 `json:"threshold"`
		OutputFormat string  `json:"output_format"`
		MaxEvents    int64   `json:"max_events"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.IngestPort < 0 || input.IngestPort > 65535 {
		return errorResult("ingest_port must be 1-65535"), nil
	}
	if input.WindowMS < 0 || input.WindowMS > maxCorrelatorWindowMS {
		return errorResult(fmt.Sprintf("window_ms must be 1-%d", maxCorrelatorWindowMS)), nil
	}
	if input.Threshold < 0.0 || input.Threshold > 1.0 {
		return errorResult("threshold must be between 0.0 and 1.0"), nil
	}
	if input.OutputFormat != "" && !validCorrelatorOutputFormats[input.OutputFormat] {
		return errorResult("invalid output_format: must be one of json, csv, syslog"), nil
	}
	if input.MaxEvents < 0 || input.MaxEvents > maxCorrelatorMaxEvents {
		return errorResult(fmt.Sprintf("max_events must be 1-%d", maxCorrelatorMaxEvents)), nil
	}
	if err := validateOutputDir(input.LogsDir, "logs_dir"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := make([]string, 0, 10)
	if input.IngestPort != 0 {
		args = append(args, "--ingest-port", strconv.FormatInt(input.IngestPort, 10))
	}
	if input.WindowMS != 0 {
		args = append(args, "--window-ms", strconv.FormatInt(input.WindowMS, 10))
	}
	if input.Threshold != 0.0 {
		args = append(args, "--threshold", strconv.FormatFloat(input.Threshold, 'f', -1, 64))
	}
	if input.OutputFormat != "" {
		args = append(args, "--output", input.OutputFormat)
	}
	if input.MaxEvents != 0 {
		args = append(args, "--max-events", strconv.FormatInt(input.MaxEvents, 10))
	}

	// The manager needs the output paths up front, so the per-process suffix
	// is generated here rather than by Start.
	suffix := defenseRandomSuffix()
	stdoutPath := filepath.Join(input.LogsDir, "protocol-correlator-"+suffix+".log")
	stderrPath := filepath.Join(input.LogsDir, "protocol-correlator-"+suffix+".err")

	proc, err := t.mgr.Start(ctx, correlatorBinary, args, stdoutPath, stderrPath)
	if err != nil {
		return errorResult("failed to start " + correlatorBinary + ": " + err.Error()), nil
	}

	ingestPort := input.IngestPort
	if ingestPort == 0 {
		ingestPort = defaultCorrelatorIngestPort
	}
	outputFormat := input.OutputFormat
	if outputFormat == "" {
		outputFormat = "json"
	}

	var sb strings.Builder
	sb.WriteString("## StaticZero Protocol Correlator Started\n\n")
	// Fenced JSON block so campaign dataflow can reference
	// ${step_id.json.process_id} for stop/status chaining.
	daemonJSON, _ := json.Marshal(map[string]any{
		"process_id":   proc.ID,
		"pid":          proc.PID,
		"binary":       correlatorBinary,
		"ingest_port":  ingestPort,
		"stdout_path":  stdoutPath,
		"stderr_path":  stderrPath,
	})
	fmt.Fprintf(&sb, "```json\n%s\n```\n\n", daemonJSON)
	fmt.Fprintf(&sb, "- **Process ID:** %s\n", proc.ID)
	fmt.Fprintf(&sb, "- **PID:** %d\n", proc.PID)
	fmt.Fprintf(&sb, "- **Binary:** %s\n", correlatorBinary)
	fmt.Fprintf(&sb, "- **Command:** %s %s\n", correlatorBinary, strings.Join(args, " "))
	fmt.Fprintf(&sb, "- **Event ingest:** JSON lines over TCP on 127.0.0.1:%d\n", ingestPort)
	fmt.Fprintf(&sb, "- **Threat output (%s):** %s\n", outputFormat, stdoutPath)
	fmt.Fprintf(&sb, "- **Logs (stderr):** %s\n", stderrPath)
	sb.WriteString("\nNotes:\n\n")
	fmt.Fprintf(&sb, "- `telecom_correlator_stop` with process_id `%s` stops the daemon\n", proc.ID)
	fmt.Fprintf(&sb, "- `telecom_correlator_status` with process_id `%s` reports live state\n", proc.ID)
	fmt.Fprintf(&sb, "- Feed events by opening a TCP connection to 127.0.0.1:%d and writing one TelecomEvent JSON object per line ({\"timestamp_ns\":<u64>,\"layer\":\"radio|nas|transport|signaling|core|application\",\"event_type\":\"...\",\"source\":\"...\",\"target\":null,\"metadata\":{}}).\n", ingestPort)
	sb.WriteString("- Correlated threats stream to the stdout log; the daemon runs until stopped.\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
