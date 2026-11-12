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

// SDRScanTool runs `sdr-bridge --mode scan`: a receive-only LTE cell scan
// across EARFCNs. Scan results (cells with decoded MIB/SIB1) are logged to
// stdout by the bridge. Note (verified in tools/src/sdr_integration.rs): in
// scan mode the bridge performs the sweep first and then keeps serving its
// local control API until it is stopped, so the tool relies on the executor's
// timeout to bound the process lifetime; the scan output is already on stdout
// by then. No RF transmission occurs in scan mode.
type SDRScanTool struct {
	exec executor.Executor
}

func NewSDRScan(exec executor.Executor) *SDRScanTool {
	return &SDRScanTool{exec: exec}
}

func (t *SDRScanTool) Name() string { return "telecom_sdr_scan" }

func (t *SDRScanTool) Description() string {
	return "Scan LTE cells with an SDR receiver via StaticZero sdr-bridge (--mode scan): sweeps EARFCNs, decodes MIB/SIB1, and reports PCI, RSRP, MCC/MNC, TAC, and cell ID to stdout. Receive-only. The bridge serves its control API after the sweep until the executor timeout stops it, so treat the call as long-running." + authorizedUseNotice
}

func (t *SDRScanTool) InputSchema() json.RawMessage {
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
			"scan_bands": {
				"type": "string",
				"description": "Band scan range: \"all-lte\" or a comma-separated EARFCN list (e.g. \"100,2750,6150\"); defaults to all-lte"
			}
		}
	}`)
}

type sdrScanInput struct {
	SdrType      string `json:"sdr_type,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	FrequencyHz  int64  `json:"frequency_hz,omitempty"`
	SampleRateHz int64  `json:"sample_rate_hz,omitempty"`
	GainDB       int64  `json:"gain_db,omitempty"`
	BandwidthHz  int64  `json:"bandwidth_hz,omitempty"`
	ScanBands    string `json:"scan_bands,omitempty"`
}

// Numeric bounds mirror the sdr-bridge defaults and plausible SDR hardware
// limits (HackRF tops out at 6 GHz, the highest of the supported devices).
const (
	defaultSDRFrequencyHz  = 2620000000
	defaultSDRSampleRateHz = 20000000
	defaultSDRGainDB       = 40
	defaultSDRBandwidthHz  = 20000000

	maxSDRFrequencyHz  = 6000000000
	maxSDRSampleRateHz = 100000000
	maxSDRGainDB       = 100
	maxSDRBandwidthHz  = 100000000
)

func (t *SDRScanTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input sdrScanInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.SdrType == "" {
		input.SdrType = "hackrf"
	}
	if !validSDRTypes[input.SdrType] {
		return errorResult("invalid sdr_type: must be one of hackrf, bladerf, usrp, rtlsdr, limesdr"), nil
	}

	if err := validateSafeString(input.DeviceID, "device_id"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateScanBands(input.ScanBands); err != nil {
		return errorResult(err.Error()), nil
	}

	if input.FrequencyHz < 0 {
		return errorResult("frequency_hz must be positive"), nil
	}
	if input.FrequencyHz == 0 {
		input.FrequencyHz = defaultSDRFrequencyHz
	}
	if input.FrequencyHz > maxSDRFrequencyHz {
		return errorResult(fmt.Sprintf("frequency_hz too high (max %d Hz)", maxSDRFrequencyHz)), nil
	}

	if input.SampleRateHz < 0 {
		return errorResult("sample_rate_hz must be positive"), nil
	}
	if input.SampleRateHz == 0 {
		input.SampleRateHz = defaultSDRSampleRateHz
	}
	if input.SampleRateHz > maxSDRSampleRateHz {
		return errorResult(fmt.Sprintf("sample_rate_hz too high (max %d Hz)", maxSDRSampleRateHz)), nil
	}

	if input.GainDB < 0 {
		return errorResult("gain_db must not be negative"), nil
	}
	if input.GainDB == 0 {
		input.GainDB = defaultSDRGainDB
	}
	if input.GainDB > maxSDRGainDB {
		return errorResult(fmt.Sprintf("gain_db too high (max %d dB)", maxSDRGainDB)), nil
	}

	if input.BandwidthHz < 0 {
		return errorResult("bandwidth_hz must be positive"), nil
	}
	if input.BandwidthHz == 0 {
		input.BandwidthHz = defaultSDRBandwidthHz
	}
	if input.BandwidthHz > maxSDRBandwidthHz {
		return errorResult(fmt.Sprintf("bandwidth_hz too high (max %d Hz)", maxSDRBandwidthHz)), nil
	}

	args := []string{
		"--mode", "scan",
		"--sdr-type", input.SdrType,
		"--frequency", strconv.FormatInt(input.FrequencyHz, 10),
		"--sample-rate", strconv.FormatInt(input.SampleRateHz, 10),
		"--gain", strconv.FormatInt(input.GainDB, 10),
		"--bandwidth", strconv.FormatInt(input.BandwidthHz, 10),
	}
	if input.DeviceID != "" {
		args = append(args, "--device-id", input.DeviceID)
	}
	if input.ScanBands != "" {
		args = append(args, "--scan-bands", input.ScanBands)
	}

	result, err := t.exec.Run(ctx, "sdr-bridge", args...)
	if err != nil {
		stderr := ""
		stdout := ""
		if result != nil {
			stderr = string(result.Stderr)
			stdout = string(result.Stdout)
		}
		// The bridge blocks in its control loop after the sweep; a timeout
		// with scan output already captured is still a usable result.
		if strings.Contains(err.Error(), "context deadline exceeded") && stdout != "" {
			return sdrScanResult(stdout, stderr), nil
		}
		return errorResult(fmt.Sprintf("sdr-bridge failed: %s\n%s", err.Error(), stderr)), nil
	}
	if result == nil {
		return errorResult("sdr-bridge produced no result"), nil
	}

	return sdrScanResult(string(result.Stdout), string(result.Stderr)), nil
}

func sdrScanResult(stdout, stderr string) *mcp.ToolResult {
	var sb strings.Builder
	sb.WriteString("## SDR Cell Scan\n\n")
	fmt.Fprintf(&sb, "- **Binary:** sdr-bridge (mode scan)\n\n")
	out := strings.TrimSpace(stdout)
	if out == "" {
		sb.WriteString("Scan produced no stdout output (cells with decoded MIB are logged as they are found).\n")
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
