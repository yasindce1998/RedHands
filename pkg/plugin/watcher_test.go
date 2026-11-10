package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherJSONChangesAndRemoval(t *testing.T) {
	dir := t.TempDir()
	var calls int
	w := NewWatcher(dir, time.Second, func(string) error { calls++; return nil })
	path := filepath.Join(dir, "tool.json")
	if err := os.WriteFile(path, []byte(`{"name":"one"}`), 0600); err != nil {
		t.Fatal(err)
	}
	w.scan()
	w.scan()
	if calls != 1 {
		t.Fatalf("initial reloads=%d", calls)
	}
	if err := os.WriteFile(path, []byte(`{"name":"two"}`), 0600); err != nil {
		t.Fatal(err)
	}
	w.scan()
	if calls != 2 {
		t.Fatal("JSON edit not detected")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.scan()
	if calls != 3 || len(w.Tracked()) != 0 {
		t.Fatal("removal not detected")
	}
}

func TestWatcherStopIdempotent(t *testing.T) {
	w := NewWatcher(t.TempDir(), -time.Second, nil)
	w.Start()
	w.Start()
	w.Stop()
	w.Stop()
}
