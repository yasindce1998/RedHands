//go:build livebin

// TestLiveFlagSurface runs the real, wrapped security-tool binaries and
// verifies that the argv fragments the RedHands wrappers build are still
// accepted by them. See package livecheck for the design; run with:
//
//	go test -tags=livebin ./tools/livecheck/... -run TestLiveFlagSurface
//
// Without the livebin build tag this file (and the suite) is excluded from
// the normal CI suite, which has no security binaries on PATH.
package livecheck

import "testing"

func TestLiveFlagSurface(t *testing.T) {
	checked, skipped := 0, 0
	for _, b := range Table() {
		path := b.Lookup()
		if path == "" {
			skipped++
			t.Run(b.binary, func(t *testing.T) {
				t.Skipf("binary %s not on PATH; install it (scripts/dependencies.py install / make install-tools / Docker image) to verify the %s wrappers here", b.binary, b.wrappers)
			})
			continue
		}
		checked++
		t.Run(b.binary, func(t *testing.T) {
			b.RunChecks(t, path)
		})
	}
	t.Logf("live binary flag surface: %d binaries checked, %d skipped (not on PATH)", checked, skipped)
}
