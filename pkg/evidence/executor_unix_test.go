//go:build !windows

package evidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
)

// A local script stands in for CutyCapt so the test exercises the actual shared
// BinaryExecutor (not a mock) without a browser, display or network access.
func TestScreenshotWithRealBoundedExecutor(t *testing.T) {
	base64Path, err := exec.LookPath("base64")
	if err != nil {
		t.Skip("base64 utility unavailable")
	}
	s := newTestStore(t)
	data := pngData(t)
	flag := "-d"
	probe := exec.Command(base64Path, flag)
	probe.Stdin = bytes.NewBufferString(base64.StdEncoding.EncodeToString(data))
	if _, err := probe.Output(); err != nil {
		flag = "-D"
		probe = exec.Command(base64Path, flag)
		probe.Stdin = bytes.NewBufferString(base64.StdEncoding.EncodeToString(data))
		if _, err := probe.Output(); err != nil {
			t.Skipf("base64 decoding flag unavailable: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "capture-helper")
	script := "#!/bin/sh\nset -eu\nfor arg in \"$@\"; do\n case \"$arg\" in --out=*) output=\"${arg#--out=}\" ;; esac\ndone\n" +
		"printf '%s' '" + base64.StdEncoding.EncodeToString(data) + "' | '" + base64Path + "' " + flag + " > \"$output\"\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	e := executor.New(executor.Config{Timeout: 2, MaxOutputBytes: 1024, AllowedBinaries: map[string]string{"cutycapt": path}})
	item, err := s.Screenshot(context.Background(), "https://example.test", e)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(item.Path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("wrong screenshot: %v", err)
	}
}

func TestScreenshotRealExecutorCancellationCleansStaging(t *testing.T) {
	s := newTestStore(t)
	path := filepath.Join(t.TempDir(), "capture-helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	e := executor.New(executor.Config{Timeout: 5, MaxOutputBytes: 1024, AllowedBinaries: map[string]string{"cutycapt": path}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Screenshot(ctx, "https://example.test", e)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not propagated: %v", err)
	}
	entries, err := os.ReadDir(s.Dir())
	if err != nil || len(entries) != 0 || len(s.List()) != 0 {
		t.Fatalf("cancelled capture left data: %v %v", entries, err)
	}
}
