package telecom

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// rfTransmitWarning is appended to the description of every sdr-bridge mode
// that can transmit RF.
const rfTransmitWarning = " WARNING: this mode transmits radio frequency energy. RF transmission is regulated by law (FCC/CEPT/national telecom authorities); operating a transmitter without a license, or on licensed cellular frequencies, is illegal in most jurisdictions. Use only in shielded or cabled authorized lab environments with appropriate attenuation, never with antennas, and only on frequencies you are authorized to use."

// sdrModeInput carries the flags shared by the sdr-bridge operating modes
// (verified against tools/src/sdr_integration.rs): --sdr-type, --device-id,
// --frequency, --sample-rate, --gain, --bandwidth, plus the per-mode
// --iq-output and --control-port flags used by the blocking modes.
type sdrModeInput struct {
	SdrType      string `json:"sdr_type,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	FrequencyHz  int64  `json:"frequency_hz,omitempty"`
	SampleRateHz int64  `json:"sample_rate_hz,omitempty"`
	GainDB       int64  `json:"gain_db,omitempty"`
	BandwidthHz  int64  `json:"bandwidth_hz,omitempty"`
	IQOutput     string `json:"iq_output,omitempty"`
	ControlPort  int64  `json:"control_port,omitempty"`
}

// validateSDRModeRadio validates and defaults the shared radio parameters
// using the same bounds as telecom_sdr_scan (sdr-bridge defaults and HackRF's
// 6 GHz ceiling). It returns the flag arguments for the validated fields.
func validateSDRModeRadio(input *sdrModeInput) ([]string, error) {
	if input.SdrType == "" {
		input.SdrType = "hackrf"
	}
	if !validSDRTypes[input.SdrType] {
		return nil, fmt.Errorf("invalid sdr_type: must be one of hackrf, bladerf, usrp, rtlsdr, limesdr")
	}
	if err := validateSafeString(input.DeviceID, "device_id"); err != nil {
		return nil, err
	}

	if input.FrequencyHz < 0 {
		return nil, fmt.Errorf("frequency_hz must be positive")
	}
	if input.FrequencyHz == 0 {
		input.FrequencyHz = defaultSDRFrequencyHz
	}
	if input.FrequencyHz > maxSDRFrequencyHz {
		return nil, fmt.Errorf("frequency_hz too high (max %d Hz)", maxSDRFrequencyHz)
	}

	if input.SampleRateHz < 0 {
		return nil, fmt.Errorf("sample_rate_hz must be positive")
	}
	if input.SampleRateHz == 0 {
		input.SampleRateHz = defaultSDRSampleRateHz
	}
	if input.SampleRateHz > maxSDRSampleRateHz {
		return nil, fmt.Errorf("sample_rate_hz too high (max %d Hz)", maxSDRSampleRateHz)
	}

	if input.GainDB < 0 {
		return nil, fmt.Errorf("gain_db must not be negative")
	}
	if input.GainDB == 0 {
		input.GainDB = defaultSDRGainDB
	}
	if input.GainDB > maxSDRGainDB {
		return nil, fmt.Errorf("gain_db too high (max %d dB)", maxSDRGainDB)
	}

	if input.BandwidthHz < 0 {
		return nil, fmt.Errorf("bandwidth_hz must be positive")
	}
	if input.BandwidthHz == 0 {
		input.BandwidthHz = defaultSDRBandwidthHz
	}
	if input.BandwidthHz > maxSDRBandwidthHz {
		return nil, fmt.Errorf("bandwidth_hz too high (max %d Hz)", maxSDRBandwidthHz)
	}

	args := []string{
		"--sdr-type", input.SdrType,
		"--frequency", strconv.FormatInt(input.FrequencyHz, 10),
		"--sample-rate", strconv.FormatInt(input.SampleRateHz, 10),
		"--gain", strconv.FormatInt(input.GainDB, 10),
		"--bandwidth", strconv.FormatInt(input.BandwidthHz, 10),
	}
	if input.DeviceID != "" {
		args = append(args, "--device-id", input.DeviceID)
	}
	if input.ControlPort != 0 {
		if input.ControlPort < 1 || input.ControlPort > 65535 {
			return nil, fmt.Errorf("control_port must be 1-65535")
		}
		args = append(args, "--control-port", strconv.FormatInt(input.ControlPort, 10))
	}
	if input.IQOutput != "" {
		if err := validatePath(input.IQOutput, "iq_output"); err != nil {
			return nil, err
		}
		args = append(args, "--iq-output", input.IQOutput)
	}
	return args, nil
}

// runSDRBlockingMode executes a blocking sdr-bridge mode (capture, inject and
// relay all serve the control API and wait for Ctrl-C per sdr_integration.rs
// main()). Like telecom_sdr_scan, the executor timeout bounds the process:
// a timeout with captured stdout is a usable result, not a failure.
func runSDRBlockingMode(ctx context.Context, exec executor.Executor, mode string, args []string, title string) (*mcp.ToolResult, error) {
	fullArgs := append([]string{"--mode", mode}, args...)
	result, err := exec.Run(ctx, "sdr-bridge", fullArgs...)
	if err != nil {
		stderr := ""
		stdout := ""
		if result != nil {
			stderr = string(result.Stderr)
			stdout = string(result.Stdout)
		}
		if strings.Contains(err.Error(), "context deadline exceeded") && stdout != "" {
			return sdrModeResult(title, mode, stdout, stderr, true), nil
		}
		return errorResult(fmt.Sprintf("sdr-bridge failed: %s\n%s", err.Error(), stderr)), nil
	}
	if result == nil {
		return errorResult("sdr-bridge produced no result"), nil
	}
	return sdrModeResult(title, mode, string(result.Stdout), string(result.Stderr), false), nil
}

func sdrModeResult(title, mode, stdout, stderr string, timedOut bool) *mcp.ToolResult {
	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n\n", title)
	fmt.Fprintf(&sb, "- **Binary:** sdr-bridge (mode %s)\n", mode)
	if timedOut {
		sb.WriteString("- **Stopped by:** executor timeout (this mode blocks in its control loop until stopped; output captured up to the deadline)\n")
	} else {
		sb.WriteString("- **Stopped by:** bridge exit\n")
	}
	sb.WriteString("\n")
	out := strings.TrimSpace(stdout)
	if out == "" {
		sb.WriteString("The bridge produced no stdout output before it stopped.\n")
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

// ---------------------------------------------------------------------------
// telecom_sdr_capture — sdr-bridge --mode capture
// ---------------------------------------------------------------------------

// SDRCaptureTool runs `sdr-bridge --mode capture`: starts an IQ capture at
// the configured frequency (streaming IQ samples to --iq-output when given)
// and then serves the local control API until stopped. Verified in
// tools/src/sdr_integration.rs: capture is receive-only, has no duration or
// sample-count flag, and blocks on ctrl_c, so the executor timeout bounds it.
type SDRCaptureTool struct {
	exec executor.Executor
}

func NewSDRCapture(exec executor.Executor) *SDRCaptureTool {
	return &SDRCaptureTool{exec: exec}
}

func (t *SDRCaptureTool) Name() string { return "telecom_sdr_capture" }

func (t *SDRCaptureTool) Description() string {
	return "Capture IQ samples from an SDR receiver via StaticZero sdr-bridge (--mode capture): tunes the device, streams raw IQ data to an output file when iq_output is given, and serves the bridge's local control API (JSON over TCP on 127.0.0.1) until stopped. Receive-only; no RF transmission. There is no duration or sample-count flag in the bridge, so the capture runs until the executor timeout stops the call — treat it as long-running and configure the timeout for the capture length you need." + authorizedUseNotice
}

func (t *SDRCaptureTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"sdr_type": {
				"type": "string",
				"enum": ["hackrf", "bladerf", "usrp", "rtlsdr", "limesdr"],
				"description": "SDR device type (default hackrf)"
			},
			"device_id": {
				"type": "string",
				"description": "SDR device serial or index (optional, auto-detect if omitted)"
			},
			"frequency_hz": {
				"type": "integer",
				"minimum": 1000000,
				"maximum": 6000000000,
				"description": "Center frequency in Hz (default 2620000000, LTE Band 7 downlink)"
			},
			"sample_rate_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Sample rate in Hz (default 20000000)"
			},
			"gain_db": {
				"type": "integer",
				"minimum": 1,
				"maximum": 100,
				"description": "RF gain in dB (default 40)"
			},
			"bandwidth_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Bandwidth in Hz (default 20000000)"
			},
			"iq_output": {
				"type": "string",
				"description": "Output file path for the raw IQ sample stream (optional; for feeding captures to gr-lte, srsRAN, etc.)"
			},
			"control_port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535,
				"description": "TCP port for the bridge's local control API on 127.0.0.1 (default 7890)"
			}
		}
	}`)
}

func (t *SDRCaptureTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input sdrModeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	args, err := validateSDRModeRadio(&input)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return runSDRBlockingMode(ctx, t.exec, "capture", args, "SDR IQ Capture")
}

// ---------------------------------------------------------------------------
// telecom_sdr_inject — sdr-bridge --mode inject (HIGH IMPACT: RF transmit)
// ---------------------------------------------------------------------------

// SDRInjectTool runs `sdr-bridge --mode inject`: initializes the SDR device
// for transmission and serves the control API, whose "inject" command
// transmits crafted protocol frames (e.g. RrcConnectionRelease) on the
// configured EARFCN. Verified in tools/src/sdr_integration.rs.
type SDRInjectTool struct {
	exec executor.Executor
}

func NewSDRInject(exec executor.Executor) *SDRInjectTool {
	return &SDRInjectTool{exec: exec}
}

func (t *SDRInjectTool) Name() string { return "telecom_sdr_inject" }

func (t *SDRInjectTool) Description() string {
	return "Start an SDR transmission bridge for protocol frame injection via StaticZero sdr-bridge (--mode inject): initializes the device for TX and serves the local control API (JSON over TCP on 127.0.0.1), whose inject command transmits crafted LTE protocol frames (for example RrcConnectionRelease) on the configured frequency. HIGH IMPACT: RF transmission; frame injection against live networks is a criminal offense in most jurisdictions (fake-base-station legislation). Authorized, shielded or cabled lab environments only. The bridge blocks in its control loop until the executor timeout stops the call, so treat it as long-running." + rfTransmitWarning + authorizedUseNotice
}

func (t *SDRInjectTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"sdr_type": {
				"type": "string",
				"enum": ["hackrf", "bladerf", "usrp", "rtlsdr", "limesdr"],
				"description": "SDR device type (default hackrf)"
			},
			"device_id": {
				"type": "string",
				"description": "SDR device serial or index (optional, auto-detect if omitted)"
			},
			"frequency_hz": {
				"type": "integer",
				"minimum": 1000000,
				"maximum": 6000000000,
				"description": "Center frequency in Hz (default 2620000000, LTE Band 7 downlink)"
			},
			"sample_rate_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Sample rate in Hz (default 20000000)"
			},
			"gain_db": {
				"type": "integer",
				"minimum": 1,
				"maximum": 100,
				"description": "RF gain in dB (default 40)"
			},
			"bandwidth_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Bandwidth in Hz (default 20000000)"
			},
			"control_port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535,
				"description": "TCP port for the bridge's local control API on 127.0.0.1 (default 7890)"
			}
		}
	}`)
}

func (t *SDRInjectTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input sdrModeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	args, err := validateSDRModeRadio(&input)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return runSDRBlockingMode(ctx, t.exec, "inject", args, "SDR Frame Injection (HIGH IMPACT: RF TRANSMIT)")
}

// ---------------------------------------------------------------------------
// telecom_sdr_relay — sdr-bridge --mode relay (HIGH IMPACT: RF transmit)
// ---------------------------------------------------------------------------

// SDRRelayTool runs `sdr-bridge --mode relay`: starts an IQ capture (like
// capture mode, with optional --iq-output) and serves the control API for
// receive-and-retransmit (relay) operation. Verified in
// tools/src/sdr_integration.rs: relay shares start_capture with capture mode
// and blocks on ctrl_c.
type SDRRelayTool struct {
	exec executor.Executor
}

func NewSDRRelay(exec executor.Executor) *SDRRelayTool {
	return &SDRRelayTool{exec: exec}
}

func (t *SDRRelayTool) Name() string { return "telecom_sdr_relay" }

func (t *SDRRelayTool) Description() string {
	return "Start an SDR receive-and-retransmit relay via StaticZero sdr-bridge (--mode relay): captures IQ samples (optionally streaming them to iq_output) and serves the local control API for retransmitting received signals on the configured frequency. HIGH IMPACT: RF retransmission; relaying live cellular traffic is interception and is a criminal offense in most jurisdictions. Authorized, shielded or cabled lab environments only. The bridge blocks in its control loop until the executor timeout stops the call, so treat it as long-running." + rfTransmitWarning + authorizedUseNotice
}

func (t *SDRRelayTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"sdr_type": {
				"type": "string",
				"enum": ["hackrf", "bladerf", "usrp", "rtlsdr", "limesdr"],
				"description": "SDR device type (default hackrf)"
			},
			"device_id": {
				"type": "string",
				"description": "SDR device serial or index (optional, auto-detect if omitted)"
			},
			"frequency_hz": {
				"type": "integer",
				"minimum": 1000000,
				"maximum": 6000000000,
				"description": "Center frequency in Hz (default 2620000000, LTE Band 7 downlink)"
			},
			"sample_rate_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Sample rate in Hz (default 20000000)"
			},
			"gain_db": {
				"type": "integer",
				"minimum": 1,
				"maximum": 100,
				"description": "RF gain in dB (default 40)"
			},
			"bandwidth_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Bandwidth in Hz (default 20000000)"
			},
			"iq_output": {
				"type": "string",
				"description": "Output file path for the raw IQ sample stream of the received signal (optional)"
			},
			"control_port": {
				"type": "integer",
				"minimum": 1,
				"maximum": 65535,
				"description": "TCP port for the bridge's local control API on 127.0.0.1 (default 7890)"
			}
		}
	}`)
}

func (t *SDRRelayTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input sdrModeInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	args, err := validateSDRModeRadio(&input)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return runSDRBlockingMode(ctx, t.exec, "relay", args, "SDR Receive-and-Retransmit Relay (HIGH IMPACT: RF TRANSMIT)")
}

// ---------------------------------------------------------------------------
// telecom_sdr_selftest — sdr-bridge --mode selftest-tx (HIGH IMPACT: RF TX)
// ---------------------------------------------------------------------------

// Selftest defaults follow rf_selftest.rs SelfTestOptions::default(): 100 MHz
// is inside every supported device's range and away from licensed cellular
// bands; 2 Msps fits the RTL-SDR RX ceiling of the hardware loopback stage.
// (The raw sdr-bridge CLI defaults of 2620 MHz / 20 Msps would put the
// self-test tone in LTE Band 7 downlink, so the wrapper pins the safer
// self-test defaults instead.)
const (
	defaultSelftestFrequencyHz  = 100000000
	defaultSelftestSampleRateHz = 2000000
	defaultSelftestGainDB       = 40
	maxSelftestGainDB           = 47 // HackRF TX VGA ceiling per rf_selftest.rs
)

// SDRSelftestTool runs `sdr-bridge --mode selftest-tx`: the bridge's TX
// pipeline self-test. Verified in tools/src/sdr_integration.rs and
// rf_selftest.rs: this mode runs the self-test (software stage always;
// hardware loopback only with STATICZERO_SDR_TX=1 and cabled devices), prints
// the JSON report on stdout and EXITS — unlike capture/inject/relay/scan it
// does not block in the control loop, and it exits non-zero when the report
// says the test failed.
type SDRSelftestTool struct {
	exec executor.Executor
}

func NewSDRSelftest(exec executor.Executor) *SDRSelftestTool {
	return &SDRSelftestTool{exec: exec}
}

func (t *SDRSelftestTool) Name() string { return "telecom_sdr_selftest" }

func (t *SDRSelftestTool) Description() string {
	return "Run the StaticZero sdr-bridge RF TX pipeline self-test (--mode selftest-tx): generates a signed 8-bit I/Q CW tone, verifies the disk round trip and signal level, and — only when the bridge runs with STATICZERO_SDR_TX=1 and a cabled HackRF-to-RTL-SDR loopback is present — transmits the tone and verifies received energy. Prints a JSON report (passed flag, tone frequency, RMS levels, hardware loopback details) and exits; exits non-zero when the self-test fails, in which case the report is still returned. HIGH IMPACT: with hardware verification enabled this transmits RF; keep it cabled or shielded, never with antennas." + rfTransmitWarning + authorizedUseNotice
}

func (t *SDRSelftestTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"frequency_hz": {
				"type": "integer",
				"minimum": 1000000,
				"maximum": 6000000000,
				"description": "Center frequency for the self-test tone in Hz (default 100000000, the rf_selftest lab default that is away from licensed cellular bands; do not use licensed frequencies)"
			},
			"sample_rate_hz": {
				"type": "integer",
				"minimum": 1000,
				"maximum": 100000000,
				"description": "Sample rate for TX and RX in Hz (default 2000000; the hardware loopback RX stage tops out at 3.2 Msps)"
			},
			"gain_db": {
				"type": "integer",
				"minimum": 1,
				"maximum": 47,
				"description": "HackRF TX VGA gain in dB (default 40; hardware range 0-47)"
			}
		}
	}`)
}

type sdrSelftestInput struct {
	FrequencyHz  int64 `json:"frequency_hz,omitempty"`
	SampleRateHz int64 `json:"sample_rate_hz,omitempty"`
	GainDB       int64 `json:"gain_db,omitempty"`
}

func (t *SDRSelftestTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input sdrSelftestInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.FrequencyHz < 0 {
		return errorResult("frequency_hz must be positive"), nil
	}
	if input.FrequencyHz == 0 {
		input.FrequencyHz = defaultSelftestFrequencyHz
	}
	if input.FrequencyHz > maxSDRFrequencyHz {
		return errorResult(fmt.Sprintf("frequency_hz too high (max %d Hz)", maxSDRFrequencyHz)), nil
	}
	if input.SampleRateHz < 0 {
		return errorResult("sample_rate_hz must be positive"), nil
	}
	if input.SampleRateHz == 0 {
		input.SampleRateHz = defaultSelftestSampleRateHz
	}
	if input.SampleRateHz > maxSDRSampleRateHz {
		return errorResult(fmt.Sprintf("sample_rate_hz too high (max %d Hz)", maxSDRSampleRateHz)), nil
	}
	if input.GainDB < 0 {
		return errorResult("gain_db must not be negative"), nil
	}
	if input.GainDB == 0 {
		input.GainDB = defaultSelftestGainDB
	}
	if input.GainDB > maxSelftestGainDB {
		return errorResult(fmt.Sprintf("gain_db too high (max %d dB for the HackRF TX VGA)", maxSelftestGainDB)), nil
	}

	args := []string{
		"--mode", "selftest-tx",
		"--frequency", strconv.FormatInt(input.FrequencyHz, 10),
		"--sample-rate", strconv.FormatInt(input.SampleRateHz, 10),
		"--gain", strconv.FormatInt(input.GainDB, 10),
	}

	result, err := t.exec.Run(ctx, "sdr-bridge", args...)
	stdout := ""
	stderr := ""
	if result != nil {
		stdout = string(result.Stdout)
		stderr = string(result.Stderr)
	}
	if err != nil {
		// The bridge prints the JSON report on stdout and only then exits
		// non-zero via ensure!(report.passed, ...), so a failed self-test
		// still yields its report — surface it instead of swallowing it.
		if stdout != "" {
			return sdrSelftestResult(stdout, stderr, true), nil
		}
		return errorResult(fmt.Sprintf("sdr-bridge failed: %s\n%s", err.Error(), stderr)), nil
	}
	if result == nil {
		return errorResult("sdr-bridge produced no result"), nil
	}

	return sdrSelftestResult(stdout, stderr, false), nil
}

func sdrSelftestResult(stdout, stderr string, failed bool) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString("## SDR RF TX Self-Test (HIGH IMPACT: RF TRANSMIT)\n\n")
	if failed {
		sb.WriteString("- **Status:** SELF-TEST FAILED — the bridge exited non-zero; see the report below\n")
	} else {
		sb.WriteString("- **Status:** completed\n")
	}
	sb.WriteString("- **Binary:** sdr-bridge (mode selftest-tx)\n\n")
	report := strings.TrimSpace(stdout)
	if report == "" {
		sb.WriteString("The bridge produced no report output.\n")
	} else {
		sb.WriteString("### Self-test report\n\n```json\n")
		sb.WriteString(report)
		sb.WriteString("\n```\n")
	}
	if stderr != "" {
		sb.WriteString("\n<details><summary>stderr</summary>\n\n```\n")
		sb.WriteString(strings.TrimSpace(stderr))
		sb.WriteString("\n```\n\n</details>\n")
	}
	return textResult(sb.String())
}
