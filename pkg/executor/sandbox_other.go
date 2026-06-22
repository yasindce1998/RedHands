//go:build !linux

package executor

import "os/exec"

func applySandboxOS(cmd *exec.Cmd) {
	// No additional sandboxing on non-Linux platforms.
}
