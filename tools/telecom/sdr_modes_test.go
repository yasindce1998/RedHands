package telecom

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// newSDRModeTools returns the four sdr-bridge mode tools with a mock
// executor; this is the single source of truth for enumerating them.
func newSDRModeTools(exec executor.Executor) []mcp.Tool {
	return []mcp.Tool{
		NewSDRCapture(exec),
		NewSDRInject(exec),
		NewSDRRelay(exec),
		NewSDRSelftest(exec),
	}
}

func TestSDRModeTools_NameDescriptionSchema(t *testing.T) {
	mock := executor.NewMock()
	tools := newSDRModeTools(mock)

	wantNames := map[string]bool{
		"telecom_sdr_capture":  false,
		"telecom_sdr_inject":   false,
		"telecom_sdr_relay":    false,
		"telecom_sdr_selftest": false,
	}
	for _, tool := range tools {
		name := tool.Name()
		if _, ok := wantNames[name]; !ok {
			t.Errorf("unexpected tool name %q", name)
			continue
		}
		wantNames[name] = true

		desc := tool.Description()
		if !strings.Contains(desc, "StaticZero") {
			t.Errorf("tool %q description must mention StaticZero", name)
		}
		if !strings.Contains(desc, "authorized lab use only") {
			t.Errorf("tool %q description must carry the authorized-use notice", name)
		}

		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema(), &schema); err != nil {
			t.Errorf("tool %q: InputSchema() is invalid JSON: %v", name, err)
			continue
		}
		if tp, ok := schema["type"]; !ok || tp != "object" {
			t.Errorf("tool %q: InputSchema() missing \"type\": \"object\"", name)
		}
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("missing SDR mode tool %q", name)
		}
	}

	// RF-transmitting modes must warn about transmission licensing.
	for _, tool := range tools {
		name := tool.Name()
		if name == "telecom_sdr_inject" || name == "telecom_sdr_relay" || name == "telecom_sdr_selftest" {
			desc := tool.Description()
			for _, want := range []string{"HIGH IMPACT", "transmit", "regulated", "shielded or cabled"} {
				if !strings.Contains(desc, want) {
					t.Errorf("tool %q description must mention %q (RF transmission warning)", name, want)
				}
			}
		}
	}

	// Capture is receive-only and must not carry the RF warning.
	if strings.Contains(NewSDRCapture(mock).Description(), "WARNING: this mode transmits") {
		t.Error("telecom_sdr_capture is receive-only and must not carry the RF transmission warning")
	}
}

func TestSDRCapture_Execute_Defaults(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Starting IQ capture at 2620MHz")
	}
	tool := NewSDRCapture(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Starting IQ capture at 2620MHz") {
		t.Errorf("expected capture output in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "sdr-bridge" {
		t.Errorf("expected binary sdr-bridge, got %q", call.Binary)
	}
	assertArgs(t, call.Args, "--mode", "capture")
	assertArgs(t, call.Args, "--sdr-type", "hackrf")
	assertArgs(t, call.Args, "--frequency", "2620000000")
	assertArgs(t, call.Args, "--sample-rate", "20000000")
	assertArgs(t, call.Args, "--gain", "40")
	assertArgs(t, call.Args, "--bandwidth", "20000000")
	if strings.Contains(strings.Join(call.Args, " "), "--iq-output") {
		t.Errorf("iq_output must be omitted when unset, got: %v", call.Args)
	}
}

func TestSDRCapture_Execute_WithParams(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSDRCapture(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"sdr_type":      "usrp",
		"device_id":     "serial-7",
		"frequency_hz":  806000000,
		"sample_rate_hz": 10000000,
		"gain_db":       20,
		"bandwidth_hz":  10000000,
		"iq_output":     "/tmp/capture.iq",
		"control_port":  7901,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--mode", "capture")
	assertArgs(t, call.Args, "--sdr-type", "usrp")
	assertArgs(t, call.Args, "--device-id", "serial-7")
	assertArgs(t, call.Args, "--frequency", "806000000")
	assertArgs(t, call.Args, "--gain", "20")
	assertArgs(t, call.Args, "--iq-output", "/tmp/capture.iq")
	assertArgs(t, call.Args, "--control-port", "7901")
}

func TestSDRInject_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Control API listening on 127.0.0.1:7890")
	}
	tool := NewSDRInject(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"frequency_hz": 2685000000,
		"control_port": 7902,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--mode", "inject")
	assertArgs(t, call.Args, "--frequency", "2685000000")
	assertArgs(t, call.Args, "--control-port", "7902")
}

func TestSDRRelay_Execute(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSDRRelay(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"sdr_type": "bladerf",
		"iq_output": "/tmp/relay.iq",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--mode", "relay")
	assertArgs(t, call.Args, "--sdr-type", "bladerf")
	assertArgs(t, call.Args, "--iq-output", "/tmp/relay.iq")
}

// capture, inject and relay all block in the bridge's control loop; a
// timeout with captured stdout is a usable result (telecom_sdr_scan
// pattern).
func TestSDRBlockingModes_TimeoutWithOutputStillReturnsResult(t *testing.T) {
	modes := []struct {
		mode string
		make func(executor.Executor) mcp.Tool
	}{
		{"capture", func(e executor.Executor) mcp.Tool { return NewSDRCapture(e) }},
		{"inject", func(e executor.Executor) mcp.Tool { return NewSDRInject(e) }},
		{"relay", func(e executor.Executor) mcp.Tool { return NewSDRRelay(e) }},
	}
	for _, m := range modes {
		t.Run(m.mode, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("Starting IQ capture at 2620MHz\nControl API listening on 127.0.0.1:7890")
			}
			mock.ErrFn = func(_ string, _ []string) error {
				return &mockError{"execution cancelled or timed out: context deadline exceeded"}
			}
			result, err := m.make(mock).Execute(context.Background(), mustJSON(map[string]any{}))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsError {
				t.Fatalf("timeout with output should return the captured result, got error: %s", result.Content[0].Text)
			}
			text := result.Content[0].Text
			if !strings.Contains(text, "executor timeout") {
				t.Errorf("expected timeout note in result, got: %s", text)
			}
			if !strings.Contains(text, "Control API listening") {
				t.Errorf("expected captured bridge output in result, got: %s", text)
			}
			assertArgs(t, mock.LastCall().Args, "--mode", m.mode)
		})
	}
}

func TestSDRSelftest_Execute_Defaults(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`{"passed":true,"iq_bytes":524288,"round_trip_verified":true,"hardware_skipped":"STATICZERO_SDR_TX not set"}`)
	}
	tool := NewSDRSelftest(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, `"passed":true`) {
		t.Errorf("expected self-test report in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "sdr-bridge" {
		t.Errorf("expected binary sdr-bridge, got %q", call.Binary)
	}
	assertArgs(t, call.Args, "--mode", "selftest-tx")
	assertArgs(t, call.Args, "--frequency", "100000000")
	assertArgs(t, call.Args, "--sample-rate", "2000000")
	assertArgs(t, call.Args, "--gain", "40")
}

func TestSDRSelftest_Execute_WithParams(t *testing.T) {
	mock := executor.NewMock()
	tool := NewSDRSelftest(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"frequency_hz":  433920000,
		"sample_rate_hz": 4000000,
		"gain_db":       30,
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--frequency", "433920000")
	assertArgs(t, call.Args, "--sample-rate", "4000000")
	assertArgs(t, call.Args, "--gain", "30")
}

// The bridge prints the JSON report and only then exits non-zero via
// ensure!(report.passed, ...), so a failed self-test must still surface its
// report.
func TestSDRSelftest_FailureStillReturnsReport(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`{"passed":false,"round_trip_verified":false}`)
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"exit status 1"}
	}
	tool := NewSDRSelftest(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("failed self-test should still return the report, got error: %s", result.Content[0].Text)
	}
	text := result.Content[0].Text
	if !strings.Contains(text, "SELF-TEST FAILED") {
		t.Errorf("expected SELF-TEST FAILED status in result, got: %s", text)
	}
	if !strings.Contains(text, `"passed":false`) {
		t.Errorf("expected report JSON in result, got: %s", text)
	}
}

func TestSDRSelftest_FailureWithoutReport(t *testing.T) {
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("sdr device not found")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"exit status 1"}
	}
	tool := NewSDRSelftest(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when the bridge fails without a report")
	}
	if !strings.Contains(result.Content[0].Text, "sdr-bridge failed") {
		t.Errorf("expected failure message, got: %s", result.Content[0].Text)
	}
}

func TestSDRModes_InvalidParams(t *testing.T) {
	captureCases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"bad sdr type", map[string]any{"sdr_type": "usrp2"}, "invalid sdr_type"},
		{"frequency negative", map[string]any{"frequency_hz": -5}, "frequency_hz must be positive"},
		{"frequency too high", map[string]any{"frequency_hz": 7000000000}, "frequency_hz too high"},
		{"sample rate too high", map[string]any{"sample_rate_hz": 200000000}, "sample_rate_hz too high"},
		{"gain too high", map[string]any{"gain_db": 500}, "gain_db too high"},
		{"bandwidth negative", map[string]any{"bandwidth_hz": -1}, "bandwidth_hz must be positive"},
		{"control port too high", map[string]any{"control_port": 70000}, "control_port must be 1-65535"},
		{"control port negative", map[string]any{"control_port": -1}, "control_port must be 1-65535"},
		{"bad device id", map[string]any{"device_id": "id`id"}, "forbidden character"},
		{"bad iq output", map[string]any{"iq_output": "/tmp/a.iq;rm"}, "forbidden character"},
		{"bad json", nil, "invalid input"},
	}
	for _, tc := range captureCases {
		t.Run("capture_"+tc.name, func(t *testing.T) {
			tool := NewSDRCapture(executor.NewMock())
			var params json.RawMessage
			if tc.params == nil {
				params = json.RawMessage(`{invalid`)
			} else {
				params = mustJSON(tc.params)
			}
			result, err := tool.Execute(context.Background(), params)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}

	selftestCases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"gain above vga ceiling", map[string]any{"gain_db": 48}, "gain_db too high"},
		{"gain negative", map[string]any{"gain_db": -3}, "gain_db must not be negative"},
		{"frequency too high", map[string]any{"frequency_hz": 7000000000}, "frequency_hz too high"},
		{"sample rate negative", map[string]any{"sample_rate_hz": -1}, "sample_rate_hz must be positive"},
	}
	for _, tc := range selftestCases {
		t.Run("selftest_"+tc.name, func(t *testing.T) {
			tool := NewSDRSelftest(executor.NewMock())
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error, got success:\n%s", result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Errorf("expected %q in error, got: %s", tc.want, result.Content[0].Text)
			}
		})
	}
}

func TestSDRModes_MetacharInjection(t *testing.T) {
	fields := []struct {
		name   string
		params func(inj string) map[string]any
	}{
		{"capture_device_id", func(inj string) map[string]any {
			return map[string]any{"device_id": "serial" + inj + "evil"}
		}},
		{"capture_iq_output", func(inj string) map[string]any {
			return map[string]any{"iq_output": "/tmp/cap.iq" + inj + "evil"}
		}},
		{"inject_device_id", func(inj string) map[string]any {
			return map[string]any{"device_id": "serial" + inj + "evil"}
		}},
		{"relay_iq_output", func(inj string) map[string]any {
			return map[string]any{"iq_output": "/tmp/relay.iq" + inj + "evil"}
		}},
	}
	for _, field := range fields {
		for _, char := range shellMetachars {
			t.Run(field.name+"_char_"+charLabel(char), func(t *testing.T) {
				mock := executor.NewMock()
				var tool mcp.Tool
				switch {
				case strings.HasPrefix(field.name, "capture"):
					tool = NewSDRCapture(mock)
				case strings.HasPrefix(field.name, "inject"):
					tool = NewSDRInject(mock)
				default:
					tool = NewSDRRelay(mock)
				}
				result, err := tool.Execute(context.Background(), mustJSON(field.params(char)))
				if err != nil {
					t.Fatalf("Execute returned Go error: %v", err)
				}
				if !result.IsError {
					t.Errorf("expected rejection for metachar %q, but got success", char)
					return
				}
				if !strings.Contains(result.Content[0].Text, "forbidden character") {
					t.Errorf("expected forbidden-character error for %q, got: %s", char, result.Content[0].Text)
				}
			})
		}
	}
}
