// Package livecheck verifies that the argv strings RedHands wrappers build are
// still accepted by the real security-tool binaries they invoke.
//
// The wrappers are only ever exercised against a MockExecutor in unit tests,
// so nothing catches CLI drift when an upstream binary changes its flag
// surface (this has happened: dozens of KubeDagger wrappers once passed flags
// the released binary rejected). This package encodes, per binary, the flags
// and enum values the wrappers actually emit, plus how to verify them against
// the real binary:
//
//   - helpCheck runs the binary's help for a (sub)command and asserts that
//     every flag string the wrapper passes appears in the output. Fast,
//     side-effect free, works for nearly everything.
//   - parseCheck runs the binary with a wrapper-style argv plus a safe
//     terminator (--help or an equivalent) and asserts the combined output
//     does not contain the CLI framework's "unknown flag" error vocabulary.
//     Used when help output does not enumerate flags reliably, and to verify
//     enum values the wrappers pass.
//
// Only help/version/dry-parse invocations are performed: nothing here touches
// a network target or mutates state.
//
// The checks run via the livebin build tag:
//
//	go test -tags=livebin ./tools/livecheck/... -run TestLiveFlagSurface
package livecheck

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// defaultTimeout bounds every binary invocation. Help text prints in
// milliseconds; the slack covers cold container filesystems.
const defaultTimeout = 10 * time.Second

// unknownFlagPatterns matches the "you passed a flag or value I do not know"
// error vocabulary of the CLI frameworks used by the wrapped tools: cobra,
// clap, Go's stdlib flag package, Python argparse/optparse, perl getopt and
// custom C parsers (nmap/masscan). A dry-parse result containing one of these
// means the wrapper's argv drifted from the binary's CLI.
var unknownFlagPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)unknown flag`),
	regexp.MustCompile(`(?i)unknown option`),
	regexp.MustCompile(`(?i)unknown command`),
	regexp.MustCompile(`(?i)unknown parameter`),
	regexp.MustCompile(`(?i)unrecognized option`),
	regexp.MustCompile(`(?i)unrecognized arguments`),
	regexp.MustCompile(`(?i)unexpected argument`),
	regexp.MustCompile(`(?i)flag provided but not defined`),
	regexp.MustCompile(`(?i)no such option`),
	regexp.MustCompile(`(?i)invalid option`),
	regexp.MustCompile(`(?i)unknown long option`),
	regexp.MustCompile(`(?i)error: unknown`),
	regexp.MustCompile(`(?i)error: unexpected`),
	regexp.MustCompile(`(?i)error: unrecognized`),
	regexp.MustCompile(`(?i)unrecognized subcommand`),
}

// helpCheck asserts that strings the wrapper emits appear in the help text of
// a (sub)command.
type helpCheck struct {
	name string
	// helpArgs obtains the help text, e.g. ["--help"] or ["scan", "--help"].
	helpArgs []string
	// acceptExit lists exit codes the binary uses for successful help.
	// Empty means [0]; tools that print usage as an error (masscan, john,
	// nikto) list their own conventions.
	acceptExit []int
	// skipOn lists output substrings that mean this binary cannot produce
	// usable help for reasons outside RedHands' control: distro packaging
	// bugs (Ubuntu's whatweb launcher dies with a Ruby LoadError) or distro
	// builds that lack an option entirely (Debian/Ubuntu's core john has no
	// jumbo-only --list). When one of them appears in the output the check
	// skips with skipReason instead of failing, keeping the issue visible
	// in every run. Evaluated before acceptExit because such invocations
	// usually also exit non-zero.
	skipOn []string
	// skipReason explains every skipOn entry; it is printed in the skip
	// message so the debt stays visible.
	skipReason string
	// want lists substrings that must appear in the normalized help output:
	// flags the wrappers pass, and enum values where help documents them.
	want []string
}

// parseCheck runs the binary with a wrapper-style argv plus a safe terminator
// and asserts the CLI parser accepts every token.
type parseCheck struct {
	name string
	// argv is the wrapper-style argument vector without the binary name.
	// Values are placeholders (example paths, TEST-NET addresses) that are
	// never dereferenced because the run is terminated by terminator.
	argv []string
	// terminator is appended to argv so the binary prints usage and exits
	// instead of doing real work ("--help" almost everywhere; "-h" for nmap;
	// "--echo" for masscan; "-hh" for sqlmap). Empty means "--help".
	terminator string
	// knownDrift, when non-empty, marks a check that is EXPECTED to fail
	// because the wrapper is known to have drifted from the pinned binary.
	// Instead of failing the suite it skips with this explanation, keeping
	// the debt visible in every run until the wrapper or the pin is fixed.
	knownDrift string
}

// binaryChecks is the full check set for one binary. wrappers names the
// RedHands toolsets that invoke it, used in drift failure messages.
type binaryChecks struct {
	binary   string
	wrappers []string
	timeout  time.Duration // 0 means defaultTimeout
	help     []helpCheck
	parse    []parseCheck
}

func (b binaryChecks) runTimeout() time.Duration {
	if b.timeout != 0 {
		return b.timeout
	}
	return defaultTimeout
}

// run executes one binary invocation and returns combined stdout+stderr and
// the exit code. A non-zero exit is not itself a failure: help and dry-parse
// checks interpret the code.
func run(path string, argv []string, timeout time.Duration) (string, int, error) {
	cctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, argv...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Stdin = nil // help/dry-parse must never depend on a TTY
	err := cmd.Run()
	exit := 0
	if err != nil {
		var exitErr *exec.ExitError
		if e, ok := err.(*exec.ExitError); ok {
			exitErr = e
			exit = exitErr.ExitCode()
		} else {
			return normalize(out.String()), exit, err
		}
	}
	return normalize(out.String()), exit, nil
}

// normalize collapses all whitespace runs so flag assertions are immune to
// line wrapping in help output.
func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// checkHelp runs one help-text assertion.
func checkHelp(t T, path string, hc helpCheck, timeout time.Duration) {
	out, exit, err := run(path, hc.helpArgs, timeout)
	if err != nil {
		t.Fatalf("check %q: `%s %s` failed to run: %v", hc.name, path, strings.Join(hc.helpArgs, " "), err)
	}
	for _, s := range hc.skipOn {
		if strings.Contains(out, s) {
			t.Skipf("SKIPPED (distro quirk): flag drift check %q: `%s %s` cannot produce help (%q in output) — %s",
				hc.name, path, strings.Join(hc.helpArgs, " "), s, hc.skipReason)
		}
	}
	accept := hc.acceptExit
	if len(accept) == 0 {
		accept = []int{0}
	}
	okExit := false
	for _, c := range accept {
		if exit == c {
			okExit = true
			break
		}
	}
	if !okExit {
		t.Fatalf("flag drift check %q: `%s %s` exited %d (want one of %v); output:\n%s",
			hc.name, path, strings.Join(hc.helpArgs, " "), exit, accept, truncate(out))
	}
	for _, want := range hc.want {
		if !strings.Contains(out, want) {
			t.Errorf("flag drift: %s no longer documents %q in `%s %s` help",
				strings.TrimSuffix(path, "-client"), want, path, strings.Join(hc.helpArgs, " "))
		}
	}
}

// checkParse runs one dry-parse assertion.
func checkParse(t T, path string, pc parseCheck, timeout time.Duration) {
	terminator := pc.terminator
	if terminator == "" {
		terminator = "--help"
	}
	argv := append(append([]string{}, pc.argv...), terminator)
	out, _, err := run(path, argv, timeout)
	if err != nil {
		t.Fatalf("check %q: `%s %s` failed to run: %v", pc.name, path, strings.Join(argv, " "), err)
	}
	for _, pat := range unknownFlagPatterns {
		if loc := pat.FindStringIndex(out); loc != nil {
			end := loc[1] + 80
			if end > len(out) {
				end = len(out)
			}
			if pc.knownDrift != "" {
				t.Skipf("KNOWN CLI DRIFT: `%s %s` is rejected by the pinned binary: %q — %s", path, strings.Join(pc.argv, " "), out[loc[0]:end], pc.knownDrift)
			}
			t.Errorf("flag drift: `%s %s` was rejected by %s: %q; output:\n%s",
				path, strings.Join(pc.argv, " "), path, out[loc[0]:end], truncate(out))
			return
		}
	}
}

func truncate(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "\n...[truncated]"
	}
	return s
}

// T is the subset of testing.T used by the checks.
type T interface {
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	Skipf(format string, args ...any)
}

// Lookup returns the binary's path on PATH, or "" when it is missing.
func (b binaryChecks) Lookup() string {
	path, err := exec.LookPath(b.binary)
	if err != nil {
		return ""
	}
	return path
}

// RunChecks executes every check registered for one binary against path.
func (b binaryChecks) RunChecks(t T, path string) {
	for _, hc := range b.help {
		checkHelp(t, path, hc, b.runTimeout())
	}
	for _, pc := range b.parse {
		checkParse(t, path, pc, b.runTimeout())
	}
}

// Table returns every registered binary check set.
func Table() []binaryChecks {
	return flagSurfaceTable
}
