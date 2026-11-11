package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadRegularFile refuses final-component symlinks and special files, bounds
// memory use, and confines path resolution (including parent symlinks) to root.
// Store directories must still be owned by the server, not untrusted local users.
func ReadRegularFile(root *os.Root, name string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("file size limit must be positive")
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds size limit", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit", name)
	}
	return data, nil
}

// WriteFileInRoot atomically replaces one direct child of root. Temporary files
// are exclusive, private and rooted, so a symlink cannot redirect their writes.
func WriteFileInRoot(root *os.Root, name string, data []byte) error {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return fmt.Errorf("expected a direct-child filename")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	tmp := ".redhands-" + hex.EncodeToString(token[:])
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, name); err != nil {
		return err
	}
	if err := syncRoot(root); err != nil {
		return &DurabilityError{Err: err}
	}
	return nil
}
