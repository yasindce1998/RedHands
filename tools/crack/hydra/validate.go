package hydra

import (
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// shellMetachars mirrors the forbidden-character set enforced by the binary
// executor (pkg/executor/sandbox.go): any argument containing one of these
// is rejected before launch. Validating here produces actionable errors
// instead of opaque executor failures. Characters hydra legitimately needs
// are deliberately NOT forbidden: ':' and '^' (http-form module options),
// '/' (paths), '=' (form fields), and quotes/backslashes in passwords.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

// serviceList enumerates the commonly attacked hydra service modules exposed
// by the hydra_attack schema enum.
var serviceList = []string{
	"ssh", "ftp", "telnet", "smtp",
	"http-get", "http-post-form", "https-get", "https-post-form",
	"smb", "rdp", "mysql", "mssql", "postgresql", "ldap3", "vnc", "redis", "snmp",
}

var validServices = func() map[string]bool {
	m := make(map[string]bool, len(serviceList))
	for _, s := range serviceList {
		m[s] = true
	}
	return m
}()

func validateSafeString(s, field string) error {
	if s == "" {
		return nil
	}
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

func validateRequired(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	return validateSafeString(s, field)
}

// validateExistingFile requires a metachar-free path to an existing regular
// file. Hydra reads wordlists from the local filesystem of the host it runs
// on, so a local existence check is correct here.
func validateExistingFile(path, field string) error {
	if err := validateRequired(path, field); err != nil {
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
	if info.Size() > 1<<30 {
		return fmt.Errorf("%s is too large (%d bytes, max %d): %s", field, info.Size(), 1<<30, path)
	}
	return nil
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
