package kubedagger

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

var (
	namespaceRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}
)

func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address is required")
	}
	if net.ParseIP(ip) == nil {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("invalid IP address or CIDR: %s", ip)
		}
	}
	return nil
}

func validateNamespace(ns string) error {
	if ns == "" {
		return nil
	}
	if len(ns) > 63 {
		return fmt.Errorf("namespace too long (max 63 chars)")
	}
	if !namespaceRegex.MatchString(ns) {
		return fmt.Errorf("invalid namespace: must be lowercase alphanumeric with dashes")
	}
	return nil
}

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

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
