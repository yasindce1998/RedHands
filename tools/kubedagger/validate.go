package kubedagger

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
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
	if ns == "all" {
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

// validateIPv4 checks that s is a plain IPv4 address (empty is allowed).
func validateIPv4(ip string) error {
	if ip == "" {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return nil
}

// validateIPPort checks that s is an "ip:port" pair (empty is allowed).
func validateIPPort(s string) error {
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid ip:port pair: %s", s)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address in %q", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port in %q", s)
	}
	return nil
}

// validatePIDList checks that s is a comma-separated list of positive PIDs.
func validatePIDList(s string) error {
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("PID list contains an empty entry")
		}
		pid, err := strconv.Atoi(part)
		if err != nil || pid < 1 {
			return fmt.Errorf("invalid PID: %s", part)
		}
	}
	return nil
}
