package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// maxBackgroundStreamBytes caps each captured output stream of a background
// process (stdout and stderr each). Daemons can run for a long time; the cap
// prevents unbounded disk growth. Past the cap, output is dropped and the
// status reports truncation.
const maxBackgroundStreamBytes = 256 * 1024 * 1024

// BackgroundProcess describes a managed long-running process.
type BackgroundProcess struct {
	ID         string    `json:"id"`
	Binary     string    `json:"binary"`
	Args       []string  `json:"args,omitempty"`
	PID        int       `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
	StdoutPath string    `json:"stdout_path,omitempty"`
	StderrPath string    `json:"stderr_path,omitempty"`
}

// BackgroundStatus is the live state of a managed process.
type BackgroundStatus struct {
	BackgroundProcess
	Running         bool      `json:"running"`
	EndedAt         time.Time `json:"ended_at,omitempty"`
	ExitCode        int       `json:"exit_code,omitempty"`
	StdoutTruncated bool      `json:"stdout_truncated,omitempty"`
	StderrTruncated bool      `json:"stderr_truncated,omitempty"`
}

type managedProcess struct {
	proc    BackgroundProcess
	cmd     *exec.Cmd
	status  BackgroundStatus
	done    chan struct{}
	mu      sync.Mutex // guards the status copy below
	stopped bool       // Stop was requested by an operator
}

// BackgroundManager starts, tracks, and stops long-running processes using
// the same binary allowlist and argument validation as BinaryExecutor. It is
// meant for defense-engine daemons whose output streams to files that other
// tools parse.
type BackgroundManager struct {
	cfg   Config
	mu    sync.Mutex
	procs map[string]*managedProcess
}

// NewBackgroundManager creates a manager sharing the executor configuration
// (allowlist, output limits).
func NewBackgroundManager(cfg Config) *BackgroundManager {
	return &BackgroundManager{cfg: cfg, procs: make(map[string]*managedProcess)}
}

// secretFlagValues lists argument names whose following value is a secret.
// Values after these flags are redacted wherever the command line is
// reported, so status output never echoes key material.
var secretFlagValues = map[string]bool{
	"-psk": true, "--psk": true,
	"-key": true, "--key": true,
	"--api-key": true,
	"--obfusc-key": true, "-obfusc-key": true,
	"--webui-token": true, "-webui-token": true,
	"--cert-key": true, "--key-file": true, "-key-file": true,
}

// redactArgs returns a copy of args with values following secret-bearing
// flags replaced by REDACTED.
func redactArgs(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for i := 0; i < len(redacted)-1; i++ {
		if secretFlagValues[redacted[i]] {
			redacted[i+1] = "REDACTED"
		}
	}
	return redacted
}

// Start launches a background process. stdoutPath and stderrPath must be
// absolute or relative file paths in existing directories; the files are
// created or truncated with 0600 permissions. The process runs in its own
// process group and is killed (SIGKILL) when the server exits.
func (m *BackgroundManager) Start(ctx context.Context, binary string, args []string, stdoutPath, stderrPath string) (*BackgroundProcess, error) {
	binPath, ok := m.cfg.AllowedBinaries[binary]
	if !ok {
		return nil, fmt.Errorf("binary not allowed: %s", binary)
	}
	if err := validateArgs(args); err != nil {
		return nil, fmt.Errorf("argument validation failed: %w", err)
	}
	if err := validateOutputPath(stdoutPath); err != nil {
		return nil, fmt.Errorf("stdout path: %w", err)
	}
	if err := validateOutputPath(stderrPath); err != nil {
		return nil, fmt.Errorf("stderr path: %w", err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	id := "proc_" + randomID()
	stdout, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open stdout file: %w", err)
	}
	stderr, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("open stderr file: %w", err)
	}

	cmd := exec.Command(binPath, args...)
	applySandbox(cmd)
	// applySandboxOS sets cmd.Cancel for context-driven kills, which is only
	// valid for CommandContext and would tie the daemon's life to the RPC
	// request. Background processes outlive their starting request; Stop()
	// manages their lifecycle.
	cmd.Cancel = nil
	cmd.Stdout = &cappedWriter{w: stdout, remaining: maxBackgroundStreamBytes}
	cmd.Stderr = &cappedWriter{w: stderr, remaining: maxBackgroundStreamBytes}

	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start %s: %w", binary, err)
	}

	mp := &managedProcess{
		proc: BackgroundProcess{
			ID:         id,
			Binary:     binary,
			Args:       redactArgs(args),
			PID:        cmd.Process.Pid,
			StartedAt:  time.Now().UTC(),
			StdoutPath: stdoutPath,
			StderrPath: stderrPath,
		},
		cmd:  cmd,
		done: make(chan struct{}),
	}
	mp.status = BackgroundStatus{BackgroundProcess: mp.proc, Running: true}

	m.mu.Lock()
	m.procs[id] = mp
	m.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		stdoutCloser := cmd.Stdout.(*cappedWriter)
		stderrCloser := cmd.Stderr.(*cappedWriter)
		mp.mu.Lock()
		mp.status.Running = false
		mp.status.EndedAt = time.Now().UTC()
		if cmd.ProcessState != nil {
			mp.status.ExitCode = cmd.ProcessState.ExitCode()
		}
		mp.status.StdoutTruncated = stdoutCloser.truncated
		mp.status.StderrTruncated = stderrCloser.truncated
		mp.mu.Unlock()
		_ = stdout.Close()
		_ = stderr.Close()
		close(mp.done)
	}()

	proc := mp.proc
	return &proc, nil
}

// Stop terminates a background process: SIGTERM to its process group, then
// SIGKILL after five seconds. Stopping an unknown ID is an error; stopping an
// already-exited process is a no-op.
func (m *BackgroundManager) Stop(id string) error {
	m.mu.Lock()
	mp, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("unknown process: %s", id)
	}

	mp.mu.Lock()
	running := mp.status.Running
	mp.stopped = true
	mp.mu.Unlock()
	if !running {
		return nil
	}

	// The process group gets the signals (Setpgid in applySandbox).
	if mp.cmd.Process != nil {
		_ = signalProcessGroup(mp.cmd.Process.Pid, syscall.SIGTERM)
	}
	select {
	case <-mp.done:
	case <-time.After(5 * time.Second):
		if mp.cmd.Process != nil {
			_ = signalProcessGroup(mp.cmd.Process.Pid, syscall.SIGKILL)
		}
		select {
		case <-mp.done:
		case <-time.After(2 * time.Second):
		}
	}
	return nil
}

// Status returns the live state of one process.
func (m *BackgroundManager) Status(id string) (*BackgroundStatus, error) {
	m.mu.Lock()
	mp, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown process: %s", id)
	}
	mp.mu.Lock()
	defer mp.mu.Unlock()
	status := mp.status
	return &status, nil
}

// List returns the state of every managed process.
func (m *BackgroundManager) List() []BackgroundStatus {
	m.mu.Lock()
	procs := make([]*managedProcess, 0, len(m.procs))
	for _, mp := range m.procs {
		procs = append(procs, mp)
	}
	m.mu.Unlock()

	statuses := make([]BackgroundStatus, 0, len(procs))
	for _, mp := range procs {
		mp.mu.Lock()
		statuses = append(statuses, mp.status)
		mp.mu.Unlock()
	}
	return statuses
}

// StopAll terminates every running process (used on server shutdown).
func (m *BackgroundManager) StopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.procs))
	for id := range m.procs {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Stop(id)
	}
}

func validateOutputPath(path string) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	if len(path) > 4096 {
		return fmt.Errorf("path too long")
	}
	return nil
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// cappedWriter wraps a file write with a hard byte budget.
type cappedWriter struct {
	w         io.Writer
	remaining int64
	truncated bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.truncated = true
		return len(p), nil // swallow further output
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
		c.truncated = true
	}
	n, err := c.w.Write(p)
	c.remaining -= int64(n)
	return n, err
}
