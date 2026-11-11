//go:build windows

package storage

import "os"

// Windows does not support syncing directory handles with os.File.Sync.
func syncDirectory(string) error { return nil }

func syncRoot(*os.Root) error { return nil }
