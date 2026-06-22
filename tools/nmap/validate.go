package nmap

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	portSpecPattern = regexp.MustCompile(`^[0-9TUtu:,\-]+$`)
	shellMetachars  = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r", "'", "\"", "\\"}
)

func ValidateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}

	if len(target) > 253 {
		return fmt.Errorf("target too long")
	}

	for _, meta := range shellMetachars {
		if strings.Contains(target, meta) {
			return fmt.Errorf("target contains forbidden character: %q", meta)
		}
	}

	if net.ParseIP(target) != nil {
		return nil
	}

	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}

	if hostnamePattern.MatchString(target) {
		return nil
	}

	return fmt.Errorf("invalid target format: must be IP, CIDR, or hostname")
}

func ValidatePorts(ports string) error {
	if ports == "" {
		return nil
	}

	if len(ports) > 1024 {
		return fmt.Errorf("port specification too long")
	}

	if !portSpecPattern.MatchString(ports) {
		return fmt.Errorf("invalid port specification: only digits, commas, hyphens, and T:/U: prefixes allowed")
	}

	return nil
}
