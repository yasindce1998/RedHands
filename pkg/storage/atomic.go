// Package storage provides private, atomic persistence for assessment data.
package storage

import (
	"os"
	"path/filepath"
)

// WriteFile replaces a file only after its new contents are fully written and
// synced. The temporary file is private and on the same filesystem.
func WriteFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".redhands-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
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
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
