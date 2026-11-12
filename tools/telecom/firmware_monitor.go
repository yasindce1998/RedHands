package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ---------------------------------------------------------------------------
// telecom_firmware_monitor — modem-firmware monitor
// ---------------------------------------------------------------------------

// validMonitorProtocols mirrors the protocol names documented by the Monitor
// subcommand in tools/src/modem_firmware.rs (diag, at, qmi, mbim).
var validMonitorProtocols = map[string]bool{
	"diag": true,
	"at":   true,
	"qmi":  true,
	"mbim": true,
}

func validateMonitorProtocol(protocol string) error {
	if !validMonitorProtocols[protocol] {
		return fmt.Errorf("invalid protocol: must be one of diag, at, qmi, mbim")
	}
	return nil
}

// FirmwareMonitorTool runs `modem-firmware monitor`. Verified in
// tools/src/modem_firmware.rs: the Monitor subcommand takes --device
// (default /dev/diag) and --protocol (default diag, one of diag/at/qmi/mbim)
// and then blocks forever on tokio::signal::ctrl_c(), streaming decoded
// DIAG/AT/QMI/MBIM frames to stdout as they arrive. Like telecom_sdr_scan,
// the tool therefore relies on the executor's timeout to bound the process
// lifetime: a "context deadline exceeded" error with captured stdout is a
// usable result containing everything monitored until the deadline.
type FirmwareMonitorTool struct {
	exec executor.Executor
}

func NewFirmwareMonitor(exec executor.Executor) *FirmwareMonitorTool {
	return &FirmwareMonitorTool{exec: exec}
}

func (t *FirmwareMonitorTool) Name() string { return "telecom_firmware_monitor" }

func (t *FirmwareMonitorTool) Description() string {
	return "Monitor a modem debug interface in real time (modem-firmware monitor): attaches to a device such as /dev/diag, /dev/ttyUSB0 or a QMI/MBIM control device and streams decoded DIAG/AT/QMI/MBIM messages to stdout. Blocking: the monitor runs until the executor timeout stops it (the CLI itself waits for Ctrl-C), so treat the call as long-running and read the captured output from the result. Requires access to the modem debug device (usually root). Wraps StaticZero (eBPF telecom security research); authorized lab use only."
}

func (t *FirmwareMonitorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"device": {
				"type": "string",
				"description": "Device path to monitor (default /dev/diag; e.g. /dev/ttyUSB0 for AT, a /dev/cdc-wdm* node for QMI/MBIM)"
			},
			"protocol": {
				"type": "string",
				"enum": ["diag", "at", "qmi", "mbim"],
				"description": "Device protocol to decode (default diag)"
			}
		}
	}`)
}

type firmwareMonitorInput struct {
	Device   string `json:"device,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func (t *FirmwareMonitorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input firmwareMonitorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Device == "" {
		input.Device = "/dev/diag"
	}
	// The device is typically a character device (or a serial node) the CLI
	// opens at runtime, so only metachar/path sanity is enforced here — not
	// existence, which would break hosts whose modem is attached later.
	if err := validatePath(input.Device, "device"); err != nil {
		return errorResult(err.Error()), nil
	}
	if input.Protocol == "" {
		input.Protocol = "diag"
	}
	if err := validateMonitorProtocol(input.Protocol); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"monitor", "--device", input.Device, "--protocol", input.Protocol}

	result, err := t.exec.Run(ctx, "modem-firmware", args...)
	if err != nil {
		stderr := ""
		stdout := ""
		if result != nil {
			stderr = string(result.Stderr)
			stdout = string(result.Stdout)
		}
		// The monitor blocks on ctrl_c; a timeout with captured monitor
		// output is still a usable (partial) result, matching the
		// telecom_sdr_scan pattern.
		if strings.Contains(err.Error(), "context deadline exceeded") && stdout != "" {
			return firmwareMonitorResult(stdout, stderr, true), nil
		}
		return errorResult(fmt.Sprintf("modem-firmware failed: %s\n%s", err.Error(), stderr)), nil
	}
	if result == nil {
		return errorResult("modem-firmware produced no result"), nil
	}

	return firmwareMonitorResult(string(result.Stdout), string(result.Stderr), false), nil
}

func firmwareMonitorResult(stdout, stderr string, timedOut bool) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString("## Modem Debug Interface Monitor\n\n")
	fmt.Fprintf(&sb, "- **Binary:** modem-firmware (monitor)\n")
	if timedOut {
		sb.WriteString("- **Stopped by:** executor timeout (the monitor blocks until stopped; output above the deadline is captured)\n")
	} else {
		sb.WriteString("- **Stopped by:** monitor exit\n")
	}
	sb.WriteString("\n")
	out := strings.TrimSpace(stdout)
	if out == "" {
		sb.WriteString("Monitor produced no stdout output before it stopped.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(out)
		sb.WriteString("\n```\n")
	}
	if stderr != "" {
		sb.WriteString("\n<details><summary>stderr</summary>\n\n```\n")
		sb.WriteString(strings.TrimSpace(stderr))
		sb.WriteString("\n```\n\n</details>\n")
	}
	return textResult(sb.String())
}
