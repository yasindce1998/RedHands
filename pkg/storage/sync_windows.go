//go:build windows

package storage

// Windows does not support syncing directory handles with os.File.Sync.
func syncDirectory(string) error { return nil }
