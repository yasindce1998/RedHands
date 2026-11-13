//go:build unix

package workflow

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// runLock is an exclusive advisory lock on a per-campaign lock file. It
// guarantees a single writer per workflow ID across processes (and goroutines)
// sharing a state directory, so two replicas can never interleave checkpoint
// writes for the same campaign.
type runLock struct {
	f *os.File
}

// acquireRunLock takes a non-blocking exclusive flock on
// <stateDir>/<workflowID>.lock. If the lock is already held — by this process
// or another replica — it fails fast with ErrAlreadyRunning instead of
// blocking or silently replacing the running campaign.
func acquireRunLock(stateDir, workflowID string) (*runLock, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(stateDir, workflowID+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	// flock locks are tied to the open file description, so a second open in
	// the same process conflicts just like one from another process.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("campaign %s is %w", workflowID, ErrAlreadyRunning)
	}
	return &runLock{f: f}, nil
}

// release drops the lock and closes its file descriptor. The lock file itself
// is left in place; state listings only consider *.json files.
func (l *runLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
