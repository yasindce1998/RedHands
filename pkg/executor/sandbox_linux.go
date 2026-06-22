//go:build linux

package executor

import (
	"os/exec"
	"syscall"
)

func applySandboxOS(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
}
