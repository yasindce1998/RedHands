package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T) *BackgroundManager {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	return NewBackgroundManager(Config{
		AllowedBinaries: map[string]string{"sleep": sleep, "sh": sh},
		MaxOutputBytes:  1024 * 1024,
	})
}

func TestBackgroundStartStatusStop(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	stdout := filepath.Join(dir, "out.log")
	stderr := filepath.Join(dir, "err.log")

	proc, err := m.Start(context.Background(), "sleep", []string{"60"}, stdout, stderr)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !strings.HasPrefix(proc.ID, "proc_") || proc.PID <= 0 {
		t.Fatalf("unexpected process: %+v", proc)
	}

	status, err := m.Status(proc.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Running {
		t.Fatalf("expected running process: %+v", status)
	}
	if status.StdoutPath != stdout {
		t.Errorf("stdout path not recorded: %+v", status)
	}

	if err := m.Stop(proc.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	status, err = m.Status(proc.ID)
	if err != nil {
		t.Fatalf("status after stop: %v", err)
	}
	if status.Running {
		t.Fatalf("expected stopped process: %+v", status)
	}
	if status.ExitCode == 0 {
		// SIGTERM'd sleep exits non-zero on POSIX; on platforms where the
		// exit code is unavailable the field stays zero.
		t.Logf("exit code after termination: %d", status.ExitCode)
	}

	// Stopping an exited process is a no-op; stopping unknown IDs errors.
	if err := m.Stop(proc.ID); err != nil {
		t.Fatalf("double stop should be a no-op: %v", err)
	}
	if err := m.Stop("proc_does_not_exist"); err == nil {
		t.Fatal("expected unknown-process error")
	}
}

func TestBackgroundOutputCapture(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	stdout := filepath.Join(dir, "out.log")

	proc, err := m.Start(context.Background(), "sh", []string{"-c", "printf 'daemon-alert-line1\\ndaemon-alert-line2\\n'"}, stdout, filepath.Join(dir, "err.log"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, err := m.Status(proc.ID)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if !status.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	data, err := os.ReadFile(stdout)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if !strings.Contains(string(data), "daemon-alert-line1") || !strings.Contains(string(data), "daemon-alert-line2") {
		t.Fatalf("captured output wrong: %q", data)
	}
}

func TestBackgroundAllowlistAndValidation(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out.log")

	if _, err := m.Start(context.Background(), "not-allowed", nil, out, out); err == nil {
		t.Fatal("expected allowlist rejection")
	}
	if _, err := m.Start(context.Background(), "sleep", []string{"60; rm -rf /"}, out, out); err == nil {
		t.Fatal("expected argument validation rejection")
	}
	if _, err := m.Start(context.Background(), "sleep", []string{"1"}, "", out); err == nil {
		t.Fatal("expected empty-path rejection")
	}
}

func TestBackgroundListAndStopAll(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		_, err := m.Start(context.Background(), "sleep", []string{"60"}, filepath.Join(dir, "o"+string(rune('a'+i))), filepath.Join(dir, "e"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 processes, got %d", len(list))
	}
	m.StopAll()
	time.Sleep(100 * time.Millisecond)
	for _, status := range m.List() {
		if status.Running {
			t.Fatalf("process still running after StopAll: %+v", status)
		}
	}
}

func TestBackgroundRedactsSecretArgs(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	proc, err := m.Start(context.Background(), "sh", []string{"-c", "sleep 30", "--psk", "hunter2", "--api-key", "s3cret", "--rate-limit", "10"}, filepath.Join(dir, "o"), filepath.Join(dir, "e"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = m.Stop(proc.ID) }()

	status, err := m.Status(proc.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	joined := strings.Join(status.Args, " ")
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "s3cret") {
		t.Fatalf("secret leaked in recorded args: %s", joined)
	}
	if !strings.Contains(joined, "REDACTED") {
		t.Fatalf("expected redaction marker: %s", joined)
	}
	// Non-secret values stay visible.
	if !strings.Contains(joined, "--rate-limit 10") {
		t.Fatalf("non-secret value redacted: %s", joined)
	}
}
