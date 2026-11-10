package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type Config struct {
	Timeout         int64
	AllowedBinaries map[string]string
	MaxOutputBytes  int64
}

type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
}

type Executor interface {
	Run(ctx context.Context, binary string, args ...string) (*Result, error)
}

type BinaryExecutor struct {
	cfg Config
}

func New(cfg Config) *BinaryExecutor {
	return &BinaryExecutor{cfg: cfg}
}

func (e *BinaryExecutor) Run(ctx context.Context, binary string, args ...string) (*Result, error) {
	binPath, ok := e.cfg.AllowedBinaries[binary]
	if !ok {
		return nil, fmt.Errorf("binary not allowed: %s", binary)
	}

	if err := validateArgs(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}

	ctx, cancel := withTimeout(ctx, e.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	applySandbox(cmd)
	cmd.WaitDelay = 2 * time.Second

	var stdout, stderr bytes.Buffer
	budget := &outputBudget{remaining: e.cfg.MaxOutputBytes}
	cmd.Stdout = &limitWriter{buf: &stdout, budget: budget}
	cmd.Stderr = &limitWriter{buf: &stderr, budget: budget}

	err := cmd.Run()

	result := &Result{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: budget.truncated,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if ctx.Err() != nil {
		return result, fmt.Errorf("execution cancelled or timed out: %w", ctx.Err())
	}
	if result.Truncated {
		return result, errors.New("execution output exceeded configured limit; output truncated")
	}

	if err != nil {
		return result, fmt.Errorf("execution failed (exit %d): %w", result.ExitCode, err)
	}

	return result, nil
}

type limitWriter struct {
	buf     *bytes.Buffer
	limit   int64
	written int64
	budget  *outputBudget
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int64
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	original := len(p)
	if w.budget != nil {
		w.budget.mu.Lock()
		defer w.budget.mu.Unlock()
		remaining := max(w.budget.remaining, 0)
		if int64(len(p)) > remaining {
			p = p[:remaining]
			w.budget.truncated = true
		}
		n, err := w.buf.Write(p)
		w.budget.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		return original, nil
	}
	remaining := w.limit - w.written
	if remaining <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := w.buf.Write(p)
	w.written += int64(n)
	if err != nil {
		return n, err
	}
	return original, nil
}
