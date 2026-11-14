package sbom

import (
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

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

// shellMetachars mirrors the forbidden-character set used by the cloud and
// barzakh toolsets. Sources and paths legitimately contain '/', ':', '@',
// '.', '-' and '_' (image refs, digests, purls, filesystem paths) but never
// shell metacharacters.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

// validateSource checks a syft/grype source string (image reference such as
// "alpine:latest" or "registry:..." / "docker:...", or a prefixed path such
// as "dir:/data", "sbom:/out/sbom.json") for shell metacharacters.
func validateSource(val, field string) error {
	if val == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(val) > 1000 {
		return fmt.Errorf("%s too long (max 1000 chars)", field)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(val, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validatePath checks an optional output/report path. Empty is treated as
// unset; required paths are enforced at the call site.
func validatePath(path, field string) error {
	if path == "" {
		return nil
	}
	if len(path) > 1000 {
		return fmt.Errorf("%s too long (max 1000 chars)", field)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(path, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validateCatalogers checks a --select-catalogers expression ("+python",
// "-rpm", comma-separated lists are allowed).
func validateCatalogers(val string) error {
	if val == "" {
		return nil
	}
	if len(val) > 500 {
		return fmt.Errorf("select_catalogers too long (max 500 chars)")
	}
	for _, mc := range shellMetachars {
		if strings.Contains(val, mc) {
			return fmt.Errorf("select_catalogers contains forbidden character: %q", mc)
		}
	}
	return nil
}

// validateExistingFile checks that a required input file exists (the
// sbom-file tools refuse to launch grype against a missing SBOM).
func validateExistingFile(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	if err := validatePath(path, field); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not an SBOM file", field)
	}
	return nil
}

// sbomFormats maps the wrapper's format enum onto syft -o values.
var sbomFormats = map[string]string{
	"syft-json":      "syft-json",
	"cyclonedx-json": "cyclonedx-json",
	"spdx-json":      "spdx-json",
}

// grypeSeverities are the --fail-on values grype accepts (verified against
// grype v0.121.3 grype/vulnerability/severity.go: unknown < negligible <
// low < medium < high < critical).
var grypeSeverities = []string{"negligible", "low", "medium", "high", "critical"}

// severityRank orders grype severities for the client-side severity filter
// (grype v0.121.3 has no --severity output filter flag; filtering happens on
// the JSON matches after the scan).
var severityRank = map[string]int{
	"unknown":    0,
	"negligible": 1,
	"low":        2,
	"medium":     3,
	"high":       4,
	"critical":   5,
}

// normalizeSeverity lower-cases a grype severity ("High" -> "high") so
// summaries and the severity filter can compare against the enum.
func normalizeSeverity(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
