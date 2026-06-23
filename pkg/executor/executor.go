package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type Config struct {
	Timeout         int64
	AllowedBinaries map[string]string
	MaxOutputBytes  int64
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
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

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitWriter{buf: &stdout, limit: e.cfg.MaxOutputBytes}
	cmd.Stderr = &limitWriter{buf: &stderr, limit: e.cfg.MaxOutputBytes}

	err := cmd.Run()

	result := &Result{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if ctx.Err() != nil {
		return result, fmt.Errorf("execution timed out")
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
}

func (w *limitWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.written
	if remaining <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := w.buf.Write(p)
	w.written += int64(n)
	return n, err
}
