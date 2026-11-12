package telecom

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// authorizedUseNotice is appended to every tool description.
const authorizedUseNotice = " Wraps StaticZero (eBPF telecom security research); authorized lab use only."

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

func validatePath(path, field string) error {
	if path == "" {
		return nil
	}
	return validateSafeString(path, field)
}

// validateInputFile ensures a path the wrapped CLI will read actually exists
// and is a regular file (modem-firmware fails with fs::read on anything else).
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

// validChipsets mirrors the exact chipset strings accepted by
// modem-firmware's FirmwareAnalyzer::new (tools/src/modem_firmware.rs).
var validChipsets = map[string]bool{
	"qualcomm":        true,
	"mediatek":        true,
	"samsung-shannon": true,
	"shannon":         true,
	"intel-xgold":     true,
	"intel":           true,
	"huawei-balong":   true,
	"balong":          true,
}

func validateChipset(chipset string) error {
	if chipset == "" {
		return fmt.Errorf("chipset is required")
	}
	if !validChipsets[chipset] {
		return fmt.Errorf("invalid chipset: must be one of qualcomm, mediatek, samsung-shannon, intel-xgold, huawei-balong")
	}
	return nil
}

// validSDRTypes mirrors the device types accepted by sdr-bridge's
// init_device (tools/src/sdr_integration.rs).
var validSDRTypes = map[string]bool{
	"hackrf":  true,
	"bladerf": true,
	"usrp":    true,
	"rtlsdr":  true,
	"limesdr": true,
}

var scanBandsRegex = regexp.MustCompile(`^(all-lte|[0-9]{1,10}(,[0-9]{1,10})*)$`)

// validateScanBands accepts "all-lte" or a comma-separated list of EARFCN
// integers (u32), matching sdr-bridge's lte_band_earfcns parsing.
func validateScanBands(bands string) error {
	if bands == "" {
		return nil
	}
	if !scanBandsRegex.MatchString(bands) {
		return fmt.Errorf("scan_bands must be \"all-lte\" or a comma-separated list of EARFCN integers")
	}
	if bands == "all-lte" {
		return nil
	}
	for _, part := range strings.Split(bands, ",") {
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil || v > 4294967295 {
			return fmt.Errorf("scan_bands EARFCN %q is not a valid u32", part)
		}
	}
	return nil
}

// validateBaseURL validates a defense-engine HTTP base URL. Only http/https
// schemes and loopback hosts are allowed unless allowRemote is true. Any path
// or query in the URL is discarded by callers, so only scheme+host are checked.
func validateBaseURL(raw string, allowRemote bool) (*url.URL, error) {
	if raw == "" {
		raw = defaultDefenseBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid base_url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("base_url scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("base_url host is required")
	}
	if u.User != nil {
		return nil, fmt.Errorf("base_url must not contain credentials")
	}
	if !allowRemote && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("base_url must point at a loopback host (127.0.0.1 or [::1]) unless allow_remote is true")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readArtifactIfPresent reads a JSON artifact the wrapped CLI was asked to
// write, so tool output includes the report contents, not just the log lines.
func readArtifactIfPresent(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return "", false
	}
	return string(data), true
}

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
