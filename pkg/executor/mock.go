package executor

import (
	"context"
	"sync"
)

type MockExecutor struct {
	mu         sync.Mutex
	Calls      []MockCall
	StdoutFn   func(binary string, args []string) []byte
	StderrFn   func(binary string, args []string) []byte
	ErrFn      func(binary string, args []string) error
	ExitCodeFn func(binary string, args []string) int
}

type MockCall struct {
	Binary string
	Args   []string
	// Env holds the extra environment entries passed via RunEnv, if any.
	Env []string
	// Stdin holds the stdin payload passed via RunEnv, if any.
	Stdin []byte
}

func NewMock() *MockExecutor {
	return &MockExecutor{}
}

func (m *MockExecutor) Run(ctx context.Context, binary string, args ...string) (*Result, error) {
	return m.RunEnv(ctx, RunOptions{}, binary, args...)
}

func (m *MockExecutor) RunEnv(_ context.Context, opts RunOptions, binary string, args ...string) (*Result, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, MockCall{Binary: binary, Args: args, Env: opts.Env, Stdin: opts.Stdin})
	m.mu.Unlock()

	var stdout, stderr []byte
	if m.StdoutFn != nil {
		stdout = m.StdoutFn(binary, args)
	}
	if m.StderrFn != nil {
		stderr = m.StderrFn(binary, args)
	}

	result := &Result{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: 0,
	}
	if m.ExitCodeFn != nil {
		result.ExitCode = m.ExitCodeFn(binary, args)
	}

	if m.ErrFn != nil {
		if err := m.ErrFn(binary, args); err != nil {
			return result, err
		}
	}

	return result, nil
}

func (m *MockExecutor) LastCall() MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return MockCall{}
	}
	return m.Calls[len(m.Calls)-1]
}

func (m *MockExecutor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = nil
}
