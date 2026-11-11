package evidence

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateScreenshotURL excludes local-file schemes, embedded credentials and
// ambiguous/control-character inputs. Redirects and subresources still require
// external network isolation; this is not browser-level scope enforcement.
func ValidateScreenshotURL(target string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(target, "\x00\r\n\t ") {
		return fmt.Errorf("screenshot URL must be an absolute HTTP(S) URL without credentials or whitespace")
	}
	return nil
}
