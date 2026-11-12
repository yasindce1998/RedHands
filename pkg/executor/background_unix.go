//go:build unix

package executor

import "syscall"

// signalProcessGroup sends sig to the process group created by Setpgid.
func signalProcessGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}
