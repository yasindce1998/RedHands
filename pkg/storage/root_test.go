package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRootedAtomicReplacementAndBounds(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteFileInRoot(root, "data.json", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileInRoot(root, "data.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err := ReadRegularFile(root, "data.json", 3)
	if err != nil || string(data) != "new" {
		t.Fatalf("rooted write: %s %v", data, err)
	}
	if _, err := ReadRegularFile(root, "data.json", 2); err == nil {
		t.Fatal("file size bound ignored")
	}
	for _, name := range []string{"../outside", "sub/path", ".", filepath.Join(dir, "absolute")} {
		if err := WriteFileInRoot(root, name, []byte("data")); err == nil {
			t.Fatalf("unsafe destination accepted: %q", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary files leaked")
	}
}

func TestRootedWritesDoNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := ReadRegularFile(root, "link", 100); err == nil {
		t.Fatal("symlink read accepted")
	}
	if err := WriteFileInRoot(root, "link", []byte("new")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(outside)
	if !bytes.Equal(data, []byte("keep")) {
		t.Fatal("write followed symlink")
	}
	data, err = ReadRegularFile(root, "link", 100)
	if err != nil || string(data) != "new" {
		t.Fatalf("symlink not replaced safely: %s %v", data, err)
	}
}

func TestRootedWriteFailurePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "destination"), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := WriteFileInRoot(root, "destination", []byte("new")); err == nil {
		t.Fatal("write replaced directory")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatal("failed write leaked files or changed destination")
	}
}
