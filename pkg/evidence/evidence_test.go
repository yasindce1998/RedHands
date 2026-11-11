package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/storage"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistenceRoundTripAndPortablePaths(t *testing.T) {
	s := newTestStore(t)
	output, err := s.SaveOutput("nmap", "https://example.test/path", "scan output")
	if err != nil {
		t.Fatal(err)
	}
	file, err := s.SaveFile("collector", "192.0.2.1", []byte("artifact"), ".bin")
	if err != nil {
		t.Fatal(err)
	}
	if output.ID == file.ID || output.SHA256 == "" || output.Size != 11 {
		t.Fatalf("invalid artifact metadata: %+v", output)
	}
	index, err := os.ReadFile(filepath.Join(s.Dir(), indexFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(index, []byte(s.Dir())) {
		t.Fatal("absolute path persisted")
	}
	other := filepath.Join(t.TempDir(), "moved")
	if err := os.Rename(s.Dir(), other); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(other)
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.List()
	if len(items) != 2 || items[0].ID != output.ID || items[1].ID != file.ID {
		t.Fatalf("items not restored: %+v", items)
	}
	data, err := os.ReadFile(items[0].Path)
	if err != nil || string(data) != "scan output" {
		t.Fatalf("artifact not restored: %s %v", data, err)
	}
	canonicalOther, err := filepath.EvalSymlinks(other)
	if err != nil {
		t.Fatal(err)
	}
	expectedPath := filepath.Join(canonicalOther, filepath.Base(output.Path))
	if items[0].Path != expectedPath {
		t.Fatalf("relocated artifact path = %q, want %q", items[0].Path, expectedPath)
	}
}

// macOS temporary directories commonly have a symlinked parent (/var ->
// /private/var). Reproduce that layout explicitly on every symlink-capable OS.
func TestRelocationThroughSymlinkedParent(t *testing.T) {
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s, err := NewStore(filepath.Join(alias, "original"))
	if err != nil {
		t.Fatal(err)
	}
	item, err := s.SaveOutput("tool", "host", "preserved")
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(alias, "moved")
	if err := os.Rename(s.Dir(), moved); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(moved)
	if err != nil {
		t.Fatal(err)
	}
	canonicalMoved, err := filepath.EvalSymlinks(moved)
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.List()
	if len(items) != 1 || items[0].ID != item.ID {
		t.Fatalf("relocation lost evidence: %+v", items)
	}
	if items[0].Path != filepath.Join(canonicalMoved, filepath.Base(item.Path)) {
		t.Fatalf("artifact path not canonicalized after relocation: %q", items[0].Path)
	}
	data, err := os.ReadFile(items[0].Path)
	if err != nil || string(data) != "preserved" {
		t.Fatalf("relocated artifact unreadable: %q %v", data, err)
	}
	index, err := os.ReadFile(filepath.Join(moved, indexFile))
	if err != nil {
		t.Fatal(err)
	}
	var persisted diskIndex
	if err := json.Unmarshal(index, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Items) != 1 || persisted.Items[0].Path != filepath.Base(item.Path) {
		t.Fatalf("index did not retain portable filename: %s", index)
	}
}

func TestUntrustedLabelsNeverBecomePaths(t *testing.T) {
	s := newTestStore(t)
	for _, label := range []string{"../../outside", "/absolute", `C:\Windows\file`, "https://host/path?x=1&y=2", "nested/../label"} {
		item, err := s.SaveOutput(label, label, "data")
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(item.Path) != s.Dir() || filepath.Base(item.Path) != item.ID+".txt" {
			t.Fatalf("unsafe path: %q", item.Path)
		}
	}
	for _, ext := range []string{"../out", ".png/../../out", `.\outside`, "", ".", ".tar.gz", ".toolongextension", ".png\x00"} {
		if _, err := s.SaveFile("tool", "host", []byte("data"), ext); err == nil {
			t.Fatalf("accepted unsafe extension: %q", ext)
		}
	}
	if len(s.List()) != 5 {
		t.Fatal("invalid extension mutated index")
	}
}

func TestLegacyFilesLeftUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy_host_output.txt")
	if err := os.WriteFile(path, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatal("invented metadata for legacy file")
	}
	if _, err := s.SaveOutput("new", "host", "new"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "legacy" {
		t.Fatal("legacy evidence overwritten")
	}
}

func TestIndexAndArtifactCorruptionFailClosed(t *testing.T) {
	for _, corruption := range []string{"json", "version", "null-item", "path", "duplicate", "hash", "missing", "size"} {
		t.Run(corruption, func(t *testing.T) {
			s := newTestStore(t)
			item, err := s.SaveOutput("tool", "host", "original")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.Dir(), indexFile)
			data, _ := os.ReadFile(path)
			var index diskIndex
			if err := json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "json":
				data = []byte("{broken")
			case "version":
				index.Version = 99
			case "null-item":
				index.Items = []*Item{nil}
			case "path":
				index.Items[0].Path = "../outside.txt"
			case "duplicate":
				index.Items = append(index.Items, index.Items[0])
			case "hash":
				if err := os.WriteFile(item.Path, []byte("changed!"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(item.Path); err != nil {
					t.Fatal(err)
				}
			case "size":
				index.Items[0].Size++
			}
			if corruption != "json" {
				data, err = json.Marshal(index)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(s.Dir()); err == nil {
				t.Fatal("corrupt evidence silently accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, data) {
				t.Fatal("failed load rewrote index")
			}
		})
	}
}

func TestFailedWritesDoNotPublishOrLeaveNewArtifacts(t *testing.T) {
	for _, failure := range []string{"artifact", "index"} {
		t.Run(failure, func(t *testing.T) {
			s := newTestStore(t)
			if _, err := s.SaveOutput("original", "host", "keep"); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(s.Dir(), indexFile))
			s.writeFile = func(root *os.Root, name string, data []byte) error {
				if (failure == "index" && name == indexFile) || (failure == "artifact" && name != indexFile) {
					return fmt.Errorf("injected write failure")
				}
				return storage.WriteFileInRoot(root, name, data)
			}
			if _, err := s.SaveOutput("new", "host", "discard"); err == nil {
				t.Fatal("write failure ignored")
			}
			after, _ := os.ReadFile(filepath.Join(s.Dir(), indexFile))
			if !bytes.Equal(before, after) || len(s.List()) != 1 {
				t.Fatal("failed save changed state")
			}
			entries, _ := os.ReadDir(s.Dir())
			if len(entries) != 2 {
				t.Fatalf("new artifact leaked: %v", entries)
			}
			reopened, err := NewStore(s.Dir())
			if err != nil || len(reopened.List()) != 1 {
				t.Fatalf("old state not recoverable: %v", err)
			}
		})
	}
}

func TestCommittedIndexWarningKeepsArtifact(t *testing.T) {
	s := newTestStore(t)
	s.writeFile = func(root *os.Root, name string, data []byte) error {
		if err := storage.WriteFileInRoot(root, name, data); err != nil {
			return err
		}
		if name == indexFile {
			return &storage.DurabilityError{Err: errors.New("injected directory sync failure")}
		}
		return nil
	}
	item, err := s.SaveOutput("tool", "host", "data")
	if item == nil || !storage.Committed(err) || len(s.List()) != 1 {
		t.Fatalf("committed save rolled back: %+v %v", item, err)
	}
	reopened, err := NewStore(s.Dir())
	if err != nil || len(reopened.List()) != 1 {
		t.Fatalf("committed artifact missing: %v", err)
	}
}

func TestCommittedArtifactWarningStillIndexesFile(t *testing.T) {
	s := newTestStore(t)
	s.writeFile = func(root *os.Root, name string, data []byte) error {
		if err := storage.WriteFileInRoot(root, name, data); err != nil {
			return err
		}
		if name != indexFile {
			return &storage.DurabilityError{Err: errors.New("injected artifact sync failure")}
		}
		return nil
	}
	item, err := s.SaveOutput("tool", "host", "data")
	if item == nil || !storage.Committed(err) {
		t.Fatalf("committed artifact warning lost: %+v %v", item, err)
	}
	reopened, err := NewStore(s.Dir())
	if err != nil || len(reopened.List()) != 1 {
		t.Fatalf("committed artifact not indexed: %v", err)
	}
}

func TestConcurrentSavesAndReturnedCopies(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			item, err := s.SaveOutput("tool", fmt.Sprint(i), "data")
			if err != nil {
				t.Error(err)
				return
			}
			item.Host = "mutated"
			for _, copyItem := range s.List() {
				copyItem.Tool = "mutated"
			}
		})
	}
	wg.Wait()
	reopened, err := NewStore(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 12 {
		t.Fatal("concurrent saves lost entries")
	}
	for _, item := range s.List() {
		if item.Tool != "tool" || item.Host == "mutated" {
			t.Fatal("caller changed internal state")
		}
	}
}

type screenshotExecutor func(context.Context, string, ...string) (*executor.Result, error)

func (f screenshotExecutor) Run(ctx context.Context, binary string, args ...string) (*executor.Result, error) {
	return f(ctx, binary, args...)
}

func pngData(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func screenshotOutput(args []string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--out=") {
			return strings.TrimPrefix(arg, "--out=")
		}
	}
	return ""
}

func TestScreenshotUsesExecutorAndPersistsVerifiedPNG(t *testing.T) {
	s := newTestStore(t)
	data := pngData(t)
	var stage string
	exec := screenshotExecutor(func(ctx context.Context, binary string, args ...string) (*executor.Result, error) {
		if binary != "cutycapt" {
			t.Fatalf("wrong binary %s", binary)
		}
		stage = filepath.Dir(screenshotOutput(args))
		info, err := os.Stat(stage)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			t.Fatal("screenshot staging directory is not private")
		}
		if err := os.WriteFile(screenshotOutput(args), data, 0644); err != nil {
			t.Fatal(err)
		}
		return &executor.Result{}, nil
	})
	item, err := s.Screenshot(context.Background(), "https://example.test/path", exec)
	if err != nil {
		t.Fatal(err)
	}
	if item.Type != "screenshot" || item.Tool != "cutycapt" {
		t.Fatalf("wrong screenshot metadata: %+v", item)
	}
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("staging directory not cleaned")
	}
	info, err := os.Stat(item.Path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("published screenshot is not private")
	}
	reopened, err := NewStore(s.Dir())
	if err != nil || len(reopened.List()) != 1 {
		t.Fatalf("screenshot not persisted: %v", err)
	}
}

func TestScreenshotFailuresLeaveNoArtifacts(t *testing.T) {
	for _, mode := range []string{"execution", "missing", "invalid", "truncated-png", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exec := screenshotExecutor(func(_ context.Context, _ string, args ...string) (*executor.Result, error) {
				if mode == "execution" {
					return &executor.Result{Stderr: []byte("sensitive-output")}, errors.New("failed")
				}
				if mode == "invalid" {
					if err := os.WriteFile(screenshotOutput(args), []byte("not a PNG"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "truncated-png" {
					data := pngData(t)
					if err := os.WriteFile(screenshotOutput(args), data[:33], 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "cancelled" {
					cancel()
				}
				return &executor.Result{}, nil
			})
			if _, err := s.Screenshot(ctx, "https://example.test", exec); err == nil {
				t.Fatal("failed screenshot accepted")
			}
			entries, _ := os.ReadDir(s.Dir())
			if len(entries) != 0 || len(s.List()) != 0 {
				t.Fatalf("failed screenshot left files: %v", entries)
			}
		})
	}
}

func TestArtifactAndIndexSymlinksRejected(t *testing.T) {
	for _, kind := range []string{"artifact", "index"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStore(t)
			item, err := s.SaveOutput("tool", "host", "data")
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			path := item.Path
			if kind == "index" {
				path = filepath.Join(s.Dir(), indexFile)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(outside, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := NewStore(s.Dir()); err == nil {
				t.Fatal("symlink accepted")
			}
			after, _ := os.ReadFile(outside)
			if !bytes.Equal(after, data) {
				t.Fatal("symlink target modified")
			}
		})
	}
}

func TestScreenshotSymlinkOutputRejected(t *testing.T) {
	s := newTestStore(t)
	outside := filepath.Join(t.TempDir(), "outside.png")
	if err := os.WriteFile(outside, pngData(t), 0600); err != nil {
		t.Fatal(err)
	}
	exec := screenshotExecutor(func(_ context.Context, _ string, args ...string) (*executor.Result, error) {
		if err := os.Symlink(outside, screenshotOutput(args)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		return &executor.Result{}, nil
	})
	if _, err := s.Screenshot(context.Background(), "https://example.test", exec); err == nil {
		t.Fatal("symlink output accepted")
	}
	if len(s.List()) != 0 {
		t.Fatal("invalid screenshot indexed")
	}
}

func TestScreenshotCancellationAndNonBlockingLists(t *testing.T) {
	s := newTestStore(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exec := screenshotExecutor(func(ctx context.Context, _ string, _ ...string) (*executor.Result, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	go func() { _, err := s.Screenshot(ctx, "https://example.test", exec); done <- err }()
	<-started
	listed := make(chan struct{})
	go func() { s.List(); close(listed) }()
	select {
	case <-listed:
	case <-time.After(time.Second):
		t.Fatal("screenshot held store lock during execution")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestScreenshotRejectsUnsafeURLsBeforeExecution(t *testing.T) {
	s := newTestStore(t)
	calls := 0
	exec := screenshotExecutor(func(context.Context, string, ...string) (*executor.Result, error) { calls++; return nil, nil })
	for _, target := range []string{"file:///etc/passwd", "ftp://host/file", "https://user:password@host", "http://", "/local/file", "https://host\ninvalid"} {
		if _, err := s.Screenshot(context.Background(), target, exec); err == nil {
			t.Fatalf("accepted URL %q", target)
		}
	}
	if calls != 0 {
		t.Fatal("unsafe URL reached executor")
	}
	if _, err := s.Screenshot(context.Background(), "https://host", nil); err == nil {
		t.Fatal("missing executor accepted")
	}
}

func TestArtifactAndIndexSizeLimits(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SaveFile("tool", "host", make([]byte, MaxArtifactBytes+1), ".bin"); err == nil {
		t.Fatal("oversized artifact accepted")
	}
	path := filepath.Join(s.Dir(), indexFile)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxIndexBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(s.Dir()); err == nil {
		t.Fatal("oversized index accepted")
	}
}

func TestOversizedScreenshotRejected(t *testing.T) {
	s := newTestStore(t)
	exec := screenshotExecutor(func(_ context.Context, _ string, args ...string) (*executor.Result, error) {
		f, err := os.Create(screenshotOutput(args))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(MaxArtifactBytes + 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return &executor.Result{}, nil
	})
	if _, err := s.Screenshot(context.Background(), "https://example.test", exec); err == nil {
		t.Fatal("oversized screenshot accepted")
	}
	entries, _ := os.ReadDir(s.Dir())
	if len(entries) != 0 {
		t.Fatal("oversized screenshot left staging files")
	}
}
