// Package msf wraps the Metasploit Framework command-line surface (msfvenom
// and msfconsole) for use in authorized engagements only.
//
// The binary executor forbids shell metacharacters in arguments, so
// msfconsole cannot be driven with `-x "use ...; set ...; run"`. Instead the
// console tools write a resource (.rc) file containing one validated console
// command per line (plus a trailing exit) into a caller-provided work_dir
// and run `msfconsole -q -r <file>`. Resource-file content is never an
// executor argument (so newlines are fine there), and every command in it is
// assembled from validated structured parameters, which structurally
// prevents arbitrary console-command injection.
package msf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// shellMetachars mirrors the forbidden-character set enforced by the binary
// executor (pkg/executor/sandbox.go): any argument containing one of these
// is rejected before launch. Validating here produces actionable errors
// instead of opaque executor failures. Backslash is deliberately NOT
// forbidden (it is not in the executor's set) because msfvenom badchars use
// hex escapes such as \x00\xff.
var shellMetachars = []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"}

var (
	// payloadNameRegex matches Metasploit payload and encoder names such as
	// linux/x64/meterpreter/reverse_tcp, windows/x64/shell_reverse_tcp,
	// cmd/unix/reverse_bash or x86/shikata_ga_nai.
	payloadNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9/_.+-]*$`)
	// moduleNameRegex matches full Metasploit module references including
	// the read-only module types (payload/encoder/nop) used for
	// documentation lookups.
	moduleNameRegex = regexp.MustCompile(`^(exploit|auxiliary|post|payload|encoder|nop)/[a-z0-9/_.+-]+$`)
	// runnableModuleRegex matches module types that can be loaded and
	// executed in a console session (exploit/auxiliary/post).
	runnableModuleRegex = regexp.MustCompile(`^(exploit|auxiliary|post)/[a-z0-9/_.+-]+$`)
	// optionKeyRegex matches Metasploit datastore keys such as LHOST,
	// RHOSTS, LPORT or DisablePayloadHandler.
	optionKeyRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	// platformRegex matches msfvenom platform identifiers such as linux,
	// windows, osx or nodejs.
	platformRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)
	// badcharsRegex matches concatenated printable-ASCII hex escapes such
	// as \x00\xff (each escape is backslash, x, two hex digits).
	badcharsRegex = regexp.MustCompile(`^(\\x[0-9a-fA-F]{2})*$`)
)

func validateSafeString(s, field string) error {
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

// validatePayloadName enforces the payload/encoder naming scheme.
func validatePayloadName(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !payloadNameRegex.MatchString(s) {
		return fmt.Errorf("%s must match ^[a-z0-9][a-z0-9/_.+-]*$ (e.g. linux/x64/meterpreter/reverse_tcp)", field)
	}
	return nil
}

// validateModuleName enforces a full module reference of any type
// (exploit|auxiliary|post|payload|encoder|nop).
func validateModuleName(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !moduleNameRegex.MatchString(s) {
		return fmt.Errorf("%s must match ^(exploit|auxiliary|post|payload|encoder|nop)/[a-z0-9/_.+-]+$ (e.g. exploit/multi/handler)", field)
	}
	return nil
}

// validateRunnableModule enforces an executable module reference
// (exploit|auxiliary|post only).
func validateRunnableModule(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !runnableModuleRegex.MatchString(s) {
		return fmt.Errorf("%s must match ^(exploit|auxiliary|post)/[a-z0-9/_.+-]+$ (e.g. auxiliary/scanner/portscan/tcp)", field)
	}
	return nil
}

// validateOptionMap validates datastore option keys and values and returns
// the keys sorted, so callers build deterministic command sequences.
func validateOptionMap(options map[string]string, field string) ([]string, error) {
	if len(options) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(options))
	for k, v := range options {
		if len(k) > 64 || !optionKeyRegex.MatchString(k) {
			return nil, fmt.Errorf("%s key %q must match ^[A-Za-z][A-Za-z0-9_]*$ (max 64 chars)", field, k)
		}
		if v == "" {
			return nil, fmt.Errorf("%s[%s] value must not be empty", field, k)
		}
		if err := validateSafeString(v, field+"["+k+"]"); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// validateWorkDir requires a metachar-free directory path, creating it (and
// parents) with 0700 when missing, mirroring the daemon tools' logs_dir
// handling.
func validateWorkDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("work_dir is required")
	}
	if err := validateSafeString(dir, "work_dir"); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("work_dir is a file, not a directory: %s", dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("cannot access work_dir %s: %v", dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create work_dir %s: %v", dir, err)
	}
	return nil
}

// validateOutputPath requires a metachar-free file path whose parent
// directory exists. Paths ending in .rc are refused so generated payloads
// can never be confused with (or overwrite) msfconsole resource files.
func validateOutputPath(path, field string) error {
	if err := validateRequired(path, field); err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file: %s", field, path)
	}
	if strings.EqualFold(filepath.Ext(path), ".rc") {
		return fmt.Errorf("%s must not end in .rc (reserved for msfconsole resource files): %s", field, path)
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s parent directory does not exist: %s", field, parent)
		}
		return fmt.Errorf("cannot access %s parent directory %s: %v", field, parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s parent is not a directory: %s", field, parent)
	}
	return nil
}

// validateResourceFile requires an existing .rc regular file with a
// metachar-free path and a sane size (resource files are small command
// scripts; 1 MiB is a generous ceiling).
func validateResourceFile(path string) error {
	if err := validateRequired(path, "resource_file"); err != nil {
		return err
	}
	if !strings.HasSuffix(path, ".rc") {
		return fmt.Errorf("resource_file must end in .rc: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("resource_file does not exist: %s", path)
		}
		return fmt.Errorf("cannot access resource_file %s: %v", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("resource_file is a directory, not a file: %s", path)
	}
	if info.Size() > 1<<20 {
		return fmt.Errorf("resource_file is too large (%d bytes, max %d): %s", info.Size(), 1<<20, path)
	}
	return nil
}

// writeResourceFile writes a msfconsole resource file with a random,
// collision-free name into workDir. The content is deterministic: one
// validated console command per line, always terminated by a final exit
// line so `msfconsole -q -r` exits when the script ends. The content is
// never passed as an executor argument, so newlines here are safe.
func writeResourceFile(workDir, prefix string, commands []string) (string, error) {
	if len(commands) == 0 {
		return "", fmt.Errorf("internal error: resource file requires at least one command")
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("cannot generate resource file name: %v", err)
	}
	path := filepath.Join(workDir, fmt.Sprintf("%s-%s.rc", prefix, hex.EncodeToString(rnd[:])))
	lines := make([]string, 0, len(commands)+1)
	lines = append(lines, commands...)
	lines = append(lines, "exit")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("cannot write resource file %s: %v", path, err)
	}
	return path, nil
}

func errorResult(msg string) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
