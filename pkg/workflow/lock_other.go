//go:build !unix

package workflow

// runLock is a no-op on platforms without flock(2) (e.g. Windows). The
// in-process running map still prevents same-process double starts; only
// cross-process exclusion is unavailable there.
type runLock struct{}

func acquireRunLock(stateDir, workflowID string) (*runLock, error) {
	return &runLock{}, nil
}

func (l *runLock) release() {}
