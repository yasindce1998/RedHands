//go:build windows

package executor

import (
	"os"
	"syscall"
)

// signalProcessGroup terminates a process on Windows, which has no process
// groups or graceful signals; both TERM and KILL become a hard terminate.
func signalProcessGroup(pid int, sig syscall.Signal) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
