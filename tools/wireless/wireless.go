package wireless

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// MonitorTool puts a wireless interface into monitor mode.
type MonitorTool struct {
	exec executor.Executor
}

func NewMonitor(exec executor.Executor) *MonitorTool {
	return &MonitorTool{exec: exec}
}

func (t *MonitorTool) Name() string { return "wireless_monitor" }

func (t *MonitorTool) Description() string {
	return "Put a wireless interface into monitor mode using airmon-ng."
}

func (t *MonitorTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Wireless interface name (e.g., wlan0)"
			},
			"action": {
				"type": "string",
				"enum": ["start", "stop", "check"],
				"description": "Action to perform: start, stop, or check monitor mode"
			}
		},
		"required": ["interface", "action"]
	}`)
}

type monitorInput struct {
	Interface string `json:"interface"`
	Action    string `json:"action"`
}

func (t *MonitorTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input monitorInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	validActions := map[string]bool{"start": true, "stop": true, "check": true}
	if !validActions[input.Action] {
		return errorResult("invalid action: must be start, stop, or check"), nil
	}

	args := []string{input.Action, input.Interface}

	result, err := t.exec.Run(ctx, "airmon-ng", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("airmon-ng execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	return textResult(string(result.Stdout)), nil
}

// ScanTool scans for nearby wireless networks.
type ScanTool struct {
	exec executor.Executor
}

func NewScan(exec executor.Executor) *ScanTool {
	return &ScanTool{exec: exec}
}

func (t *ScanTool) Name() string { return "wireless_scan" }

func (t *ScanTool) Description() string {
	return "Scan for nearby wireless networks using airodump-ng."
}

func (t *ScanTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Wireless interface in monitor mode (e.g., wlan0mon)"
			},
			"duration": {
				"type": "integer",
				"description": "Scan duration in seconds (default 10)"
			},
			"channel": {
				"type": "integer",
				"description": "Specific channel to scan"
			},
			"band": {
				"type": "string",
				"enum": ["a", "b", "g"],
				"description": "Wireless band to scan (a, b, or g)"
			}
		},
		"required": ["interface"]
	}`)
}

type scanInput struct {
	Interface string `json:"interface"`
	Duration  int    `json:"duration,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	Band      string `json:"band,omitempty"`
}

func (t *ScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input scanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	if input.Duration <= 0 {
		input.Duration = 10
	}

	if input.Band != "" {
		validBands := map[string]bool{"a": true, "b": true, "g": true}
		if !validBands[input.Band] {
			return errorResult("invalid band: must be a, b, or g"), nil
		}
	}

	args := []string{input.Interface}

	if input.Channel > 0 {
		args = append(args, "--channel", fmt.Sprintf("%d", input.Channel))
	}

	if input.Band != "" {
		args = append(args, "--band", input.Band)
	}

	args = append(args, "-w", "/tmp/scan", "--output-format", "csv")

	result, err := t.exec.Run(ctx, "airodump-ng", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("airodump-ng execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	return textResult(string(result.Stdout)), nil
}

// DeauthTool sends deauthentication frames.
type DeauthTool struct {
	exec executor.Executor
}

func NewDeauth(exec executor.Executor) *DeauthTool {
	return &DeauthTool{exec: exec}
}

func (t *DeauthTool) Name() string { return "wireless_deauth" }

func (t *DeauthTool) Description() string {
	return "Send deauthentication frames to disconnect clients from a network using aireplay-ng."
}

func (t *DeauthTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Wireless interface in monitor mode"
			},
			"bssid": {
				"type": "string",
				"description": "Target access point BSSID (MAC address)"
			},
			"client": {
				"type": "string",
				"description": "Target specific client MAC address (optional, broadcast if omitted)"
			},
			"count": {
				"type": "integer",
				"description": "Number of deauth frames to send (default 5)"
			}
		},
		"required": ["interface", "bssid"]
	}`)
}

type deauthInput struct {
	Interface string `json:"interface"`
	BSSID     string `json:"bssid"`
	Client    string `json:"client,omitempty"`
	Count     int    `json:"count,omitempty"`
}

func (t *DeauthTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input deauthInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	if err := validateInput(input.BSSID); err != nil {
		return errorResult("invalid bssid: " + err.Error()), nil
	}

	if input.Client != "" {
		if err := validateInput(input.Client); err != nil {
			return errorResult("invalid client: " + err.Error()), nil
		}
	}

	if input.Count <= 0 {
		input.Count = 5
	}

	args := []string{"--deauth", fmt.Sprintf("%d", input.Count), "-a", input.BSSID}

	if input.Client != "" {
		args = append(args, "-c", input.Client)
	}

	args = append(args, input.Interface)

	result, err := t.exec.Run(ctx, "aireplay-ng", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("aireplay-ng execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	return textResult(string(result.Stdout)), nil
}

// CaptureTool captures wireless handshakes.
type CaptureTool struct {
	exec executor.Executor
}

func NewCapture(exec executor.Executor) *CaptureTool {
	return &CaptureTool{exec: exec}
}

func (t *CaptureTool) Name() string { return "wireless_capture" }

func (t *CaptureTool) Description() string {
	return "Capture WPA/WPA2 handshake from a target network using airodump-ng."
}

func (t *CaptureTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Wireless interface in monitor mode"
			},
			"bssid": {
				"type": "string",
				"description": "Target access point BSSID (MAC address)"
			},
			"channel": {
				"type": "integer",
				"description": "Channel the target AP is operating on"
			},
			"output_file": {
				"type": "string",
				"description": "Output file prefix for captured data"
			},
			"duration": {
				"type": "integer",
				"description": "Capture duration in seconds"
			}
		},
		"required": ["interface", "bssid", "channel", "output_file"]
	}`)
}

type captureInput struct {
	Interface  string `json:"interface"`
	BSSID      string `json:"bssid"`
	Channel    int    `json:"channel"`
	OutputFile string `json:"output_file"`
	Duration   int    `json:"duration,omitempty"`
}

func (t *CaptureTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input captureInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Interface); err != nil {
		return errorResult("invalid interface: " + err.Error()), nil
	}

	if err := validateInput(input.BSSID); err != nil {
		return errorResult("invalid bssid: " + err.Error()), nil
	}

	if err := validateInput(input.OutputFile); err != nil {
		return errorResult("invalid output_file: " + err.Error()), nil
	}

	if input.Channel <= 0 {
		return errorResult("channel must be a positive integer"), nil
	}

	args := []string{
		"--bssid", input.BSSID,
		"--channel", fmt.Sprintf("%d", input.Channel),
		"-w", input.OutputFile,
		input.Interface,
	}

	result, err := t.exec.Run(ctx, "airodump-ng", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("airodump-ng capture failed: %s\n%s", err.Error(), stderr)), nil
	}

	return textResult(string(result.Stdout)), nil
}

// CrackTool cracks captured WPA/WPA2 handshakes.
type CrackTool struct {
	exec executor.Executor
}

func NewCrack(exec executor.Executor) *CrackTool {
	return &CrackTool{exec: exec}
}

func (t *CrackTool) Name() string { return "wireless_crack" }

func (t *CrackTool) Description() string {
	return "Crack a captured WPA/WPA2 handshake using aircrack-ng with a wordlist."
}

func (t *CrackTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"capture_file": {
				"type": "string",
				"description": "Path to the capture file containing the handshake"
			},
			"wordlist": {
				"type": "string",
				"description": "Path to the wordlist file for dictionary attack"
			},
			"bssid": {
				"type": "string",
				"description": "Target BSSID to crack (optional, used when capture contains multiple networks)"
			}
		},
		"required": ["capture_file", "wordlist"]
	}`)
}

type crackInput struct {
	CaptureFile string `json:"capture_file"`
	Wordlist    string `json:"wordlist"`
	BSSID       string `json:"bssid,omitempty"`
}

func (t *CrackTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input crackInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.CaptureFile); err != nil {
		return errorResult("invalid capture_file: " + err.Error()), nil
	}

	if err := validateInput(input.Wordlist); err != nil {
		return errorResult("invalid wordlist: " + err.Error()), nil
	}

	if input.BSSID != "" {
		if err := validateInput(input.BSSID); err != nil {
			return errorResult("invalid bssid: " + err.Error()), nil
		}
	}

	var args []string

	if input.BSSID != "" {
		args = append(args, "-b", input.BSSID)
	}

	args = append(args, "-w", input.Wordlist, input.CaptureFile)

	result, err := t.exec.Run(ctx, "aircrack-ng", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("aircrack-ng execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	return textResult(string(result.Stdout)), nil
}

// BettercapTool runs bettercap commands for wireless attacks.
type BettercapTool struct {
	exec executor.Executor
}

func NewBettercap(exec executor.Executor) *BettercapTool {
	return &BettercapTool{exec: exec}
}

func (t *BettercapTool) Name() string { return "wireless_bettercap" }

func (t *BettercapTool) Description() string {
	return "Run bettercap commands for advanced wireless network attacks and monitoring."
}

func (t *BettercapTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"interface": {
				"type": "string",
				"description": "Network interface to use"
			},
			"caplet": {
				"type": "string",
				"description": "Caplet file to load and execute"
			},
			"eval": {
				"type": "string",
				"description": "Direct bettercap command to evaluate"
			}
		}
	}`)
}

type bettercapInput struct {
	Interface string `json:"interface,omitempty"`
	Caplet    string `json:"caplet,omitempty"`
	Eval      string `json:"eval,omitempty"`
}

func (t *BettercapTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input bettercapInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Interface != "" {
		if err := validateInput(input.Interface); err != nil {
			return errorResult("invalid interface: " + err.Error()), nil
		}
	}

	if input.Caplet != "" {
		if err := validateInput(input.Caplet); err != nil {
			return errorResult("invalid caplet: " + err.Error()), nil
		}
	}

	if input.Eval != "" {
		if err := validateInput(input.Eval); err != nil {
			return errorResult("invalid eval: " + err.Error()), nil
		}
	}

	if input.Interface == "" && input.Caplet == "" && input.Eval == "" {
		return errorResult("at least one of interface, caplet, or eval must be provided"), nil
	}

	var args []string

	if input.Interface != "" {
		args = append(args, "-iface", input.Interface)
	}

	if input.Caplet != "" {
		args = append(args, "-caplet", input.Caplet)
	}

	if input.Eval != "" {
		args = append(args, "-eval", input.Eval)
	}

	result, err := t.exec.Run(ctx, "bettercap", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("bettercap execution failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		output = "bettercap command completed successfully"
	}

	return textResult(output), nil
}
