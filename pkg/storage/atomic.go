// Package storage provides private, atomic persistence for assessment data.
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A DurabilityError means replacement succeeded, but syncing its directory did
// not. Callers must not roll back memory to the old value after a committed write.
type DurabilityError struct{ Err error }

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("file replaced but directory sync failed: %v", e.Err)
}
func (e *DurabilityError) Unwrap() error { return e.Err }
func Committed(err error) bool           { var e *DurabilityError; return errors.As(err, &e) }

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
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return &DurabilityError{Err: err}
	}
	return nil
}
