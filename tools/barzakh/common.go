package barzakh

import (
	"fmt"
	"os"
	"strings"
)

// barzakhArches mirrors the ArchArg value enum accepted by barzakh-adversary
// (generate, inject-single, qemu run/dump): adversary_main.rs names them
// x86-64, aarch64, riscv64, power64, armv7.
var barzakhArches = []string{"x86-64", "aarch64", "riscv64", "power64", "armv7"}

// validateBarzakhArch checks an optional --arch value. An empty value is
// treated as unset; the CLIs then apply their own default (x86-64).
func validateBarzakhArch(arch string) error {
	if arch == "" {
		return nil
	}
	for _, a := range barzakhArches {
		if arch == a {
			return nil
		}
	}
	return fmt.Errorf("invalid arch: must be one of %s", strings.Join(barzakhArches, ", "))
}

// isValidAction reports whether action is one of the allowed values of a
// subcommand's action enum.
func isValidAction(actions []string, action string) bool {
	for _, a := range actions {
		if action == a {
			return true
		}
	}
	return false
}

// validateExistingFile ensures a path the wrapped CLI will read actually
// exists and is a regular file, so a missing input fails fast in the tool
// instead of surfacing as a binary error. Call validatePath (metacharacter
// check) first; an empty value is treated as unset.
func validateExistingFile(path, field string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file: %s", field, path)
	}
	return nil
}

// validateExistingDir ensures a directory the wrapped CLI will read (e.g. a
// corpus directory) exists. An empty value is treated as unset.
func validateExistingDir(path, field string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not accessible: %v", field, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is a file, not a directory: %s", field, path)
	}
	return nil
}
