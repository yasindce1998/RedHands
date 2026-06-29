package barzakh

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

var (
	payloadNameRegex = regexp.MustCompile(`^[a-z0-9_]+$`)
	shellMetachars   = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}
)

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

func validatePayloadName(name string) error {
	if name == "" {
		return fmt.Errorf("payload name is required")
	}
	if len(name) > 128 {
		return fmt.Errorf("payload name too long (max 128 chars)")
	}
	if !payloadNameRegex.MatchString(name) {
		return fmt.Errorf("payload name must be lowercase alphanumeric with underscores")
	}
	return nil
}

func validatePath(path, field string) error {
	if path == "" {
		return nil
	}
	return validateSafeString(path, field)
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
