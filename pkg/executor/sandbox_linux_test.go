//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProcessTreeHelper(t *testing.T) {
	if os.Getenv("REDHANDS_EXECUTOR_TREE_HELPER") != "1" {
		return
	}
	child := exec.Command("/bin/sleep", "60")
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("REDHANDS_EXECUTOR_PID_FILE"), []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
		os.Exit(3)
	}
	_ = child.Wait()
	os.Exit(0)
}

func TestCancellationKillsChildProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("REDHANDS_EXECUTOR_TREE_HELPER", "1")
	t.Setenv("REDHANDS_EXECUTOR_PID_FILE", pidFile)
	execPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	e := New(Config{Timeout: 10, AllowedBinaries: map[string]string{"helper": execPath}, MaxOutputBytes: 1024})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.Run(ctx, "helper", "-test.run=TestProcessTreeHelper"); done <- err }()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var pid int
	for pid == 0 {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(string(data))
		}
		if pid != 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("helper exited before starting: %v", err)
		case <-deadline:
			t.Fatal("helper did not start")
		case <-ticker.C:
		}
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("executor did not stop")
	}
	// An orphaned killed child may remain a zombie until the container's PID 1
	// reaps it. Either disappearance or zombie state proves it is no longer
	// running. The SIGKILL delivery and state transition are asynchronous, so
	// poll briefly before declaring the child alive.
	deadline = time.After(2 * time.Second)
	for {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		// ENOENT (already reaped) and ESRCH (task exiting mid-read) both
		// prove the child is gone.
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
		if len(fields) < 3 {
			t.Fatalf("unexpected procfs stat line: %s", data)
		}
		if fields[2] == "Z" {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("child still running after cancellation: %s", data)
		case <-ticker.C:
		}
	}
}
