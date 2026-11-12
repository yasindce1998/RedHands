// Package aegis wraps Aegis-Shadow (Linux eBPF security research platform,
// educational/VM-only) for authorized lab use only.
//
// The tools in this package deliberately NEVER execute the Aegis-Shadow
// defense/offense binaries. They operate purely on files produced by or
// consumed by those binaries (NDJSON alert logs, hot-reload runtime config)
// plus static reference data transcribed from the Aegis-Shadow sources.
// This keeps the eBPF rootkit binaries out of MCP-executable reach while
// still supporting alert triage and lab planning workflows.
package aegis

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

var (
	ttyDeviceRegex = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
	timestompRegex = regexp.MustCompile(`^[0-9]+:[0-9]+:[0-9]+:[0-9]+$`)
	ifaceRegex     = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
)

// shellMetachars mirrors the forbidden-character policy used across the
// RedHands tool wrappers.
var shellMetachars = []string{
	";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r",
}

func validateSafeString(s, field string) error {
	if len(s) > 4096 {
		return fmt.Errorf("%s too long (max 4096 chars)", field)
	}
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return fmt.Errorf("%s contains forbidden character: %q", field, mc)
		}
	}
	return nil
}

// validatePath enforces a non-empty path without shell metacharacters.
func validatePath(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	return validateSafeString(path, field)
}

// validateExistingFile enforces that path is a readable regular file no
// larger than maxSize bytes.
func validateExistingFile(path, field string, maxSize int64) error {
	if err := validatePath(path, field); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist: %s", field, path)
		}
		return fmt.Errorf("cannot access %s %s: %v", field, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file: %s", field, path)
	}
	if maxSize > 0 && info.Size() > maxSize {
		return fmt.Errorf("%s is too large (%d bytes, max %d): %s", field, info.Size(), maxSize, path)
	}
	return nil
}

// validateWritablePath enforces a non-empty metachar-free path that does not
// point at an existing directory.
func validateWritablePath(path, field string) error {
	if err := validatePath(path, field); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file: %s", field, path)
	}
	return nil
}

// validateSeverity accepts the empty string (no filter) or one of the four
// AlertRecord severity labels emitted by the defense engine.
func validateSeverity(sev string) error {
	switch sev {
	case "", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return nil
	}
	return fmt.Errorf("invalid severity %q: must be LOW, MEDIUM, HIGH or CRITICAL", sev)
}

// severityRank maps AlertRecord severity labels to the defense engine's
// numeric scale (1=Low .. 4=Critical). Unknown labels rank below LOW.
func severityRank(sev string) int {
	switch sev {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return 0
}

// validateThreshold enforces the defense daemon's 1-4 alert threshold range.
func validateThreshold(t int) error {
	if t < 1 || t > 4 {
		return fmt.Errorf("threshold must be 1 (Low), 2 (Medium), 3 (High) or 4 (Critical)")
	}
	return nil
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
