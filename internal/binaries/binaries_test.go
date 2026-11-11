package binaries

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestImpacketPipEntryPointAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix script entry point")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secretsdump.py")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got := Discover()["impacket-secretsdump"]; got != path {
		t.Fatalf("pip entry point unresolved: %q", got)
	}
	distro := filepath.Join(dir, "impacket-secretsdump")
	if err := os.WriteFile(distro, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve("impacket-secretsdump"); err != nil || got != distro {
		t.Fatalf("distro entry point not preferred: %s %v", got, err)
	}
}
