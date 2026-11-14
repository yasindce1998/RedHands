package rubeus

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// shellMetachars mirrors the forbidden-character set enforced by the binary
// executor (pkg/executor/sandbox.go): any argument containing one of these
// is rejected before launch. Validating here produces actionable errors
// instead of opaque executor failures. Characters Rubeus flag values
// legitimately need are deliberately NOT forbidden: '/' (flag style and
// SPNs), ':' (flag separator), '=' and '\' (DOMAIN\user), '^' and quotes in
// passwords.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

var (
	// base64TicketRegex matches standard base64 (RFC 4648) with optional
	// trailing '=' padding: exactly the charset Rubeus accepts for
	// /ticket:BASE64 .kirbi blobs.
	base64TicketRegex = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// hexHashRegex matches lowercase/uppercase hex strings (used for RC4
	// NTLM hashes and AES256 keys).
	hexHashRegex = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	// luidRegex matches Windows logon session IDs as accepted by Rubeus's
	// LUID parser, e.g. 0x3e7 or 0x3c4c241.
	luidRegex = regexp.MustCompile(`^0x[0-9a-fA-F]{1,16}$`)
)

func validateSafeString(s, field string) error {
	if s == "" {
		return nil
	}
	if len(s) > 65536 {
		return fmt.Errorf("%s too long (max 65536 chars)", field)
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

// validateBase64Ticket requires a non-trivial standard-base64 blob: the
// Rubeus charset [A-Za-z0-9+/] with at most two trailing '=' paddings.
// Kirbi tickets are hundreds of bytes, so anything shorter than 16
// characters is rejected as malformed input.
func validateBase64Ticket(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(s) > 65536 {
		return fmt.Errorf("%s too long (max 65536 chars)", field)
	}
	if len(s) < 16 {
		return fmt.Errorf("%s is too short to be a base64 .kirbi ticket (min 16 chars)", field)
	}
	if !base64TicketRegex.MatchString(s) {
		return fmt.Errorf("%s must be standard base64 ([A-Za-z0-9+/] with optional trailing = padding)", field)
	}
	return nil
}

// validateHexHash requires a hex string of exactly wantChars characters
// (32 for an RC4/NTLM hash, 64 for an AES256 key).
func validateHexHash(s string, wantChars int, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(s) != wantChars {
		return fmt.Errorf("%s must be exactly %d hex characters (got %d)", field, wantChars, len(s))
	}
	if !hexHashRegex.MatchString(s) {
		return fmt.Errorf("%s must contain only hex characters [0-9a-fA-F]", field)
	}
	return nil
}

// validateLUID requires a 0x-prefixed hex logon session ID, matching
// Rubeus's LUID parsing (e.g. 0x3e7).
func validateLUID(s string) error {
	if !luidRegex.MatchString(s) {
		return fmt.Errorf("must be a 0x-prefixed hex logon session ID (e.g. 0x3e7)")
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
