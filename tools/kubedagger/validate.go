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
	podNameRegex   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
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

func validatePodName(name string) error {
	if name == "" {
		return fmt.Errorf("pod name is required")
	}
	if len(name) > 253 {
		return fmt.Errorf("pod name too long (max 253 chars)")
	}
	if !podNameRegex.MatchString(name) {
		return fmt.Errorf("invalid pod name: must be lowercase alphanumeric with dashes and dots")
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

func validatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d (must be 0-65535)", port)
	}
	return nil
}

func validateTarget(target string) error {
	if target == "" {
		return nil
	}
	return validateSafeString(target, "target")
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
