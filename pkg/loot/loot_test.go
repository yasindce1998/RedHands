package loot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

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

func TestPersistenceFiltersAndIndependentCopies(t *testing.T) {
	s := newTestStore(t)
	first := &Item{Type: "file", Host: "192.0.2.1", Description: "first artifact", Data: "sensitive", Tags: []string{"lab"}}
	if err := s.Add(first); err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.CreatedAt.IsZero() {
		t.Fatal("generated metadata not returned")
	}
	first.Description = "mutated"
	first.Tags[0] = "mutated"
	if err := s.Add(&Item{Type: "hash", Host: "192.0.2.2", Description: "second artifact"}); err != nil {
		t.Fatal(err)
	}
	for _, item := range s.List("", "") {
		item.Description = "mutated"
		item.Tags = append(item.Tags, "mutated")
	}
	for _, item := range s.Search("artifact") {
		item.Data = "mutated"
	}
	if len(s.List("file", "192.0.2.1")) != 1 || len(s.List("file", "192.0.2.2")) != 0 || len(s.Search("FIRST")) != 1 {
		t.Fatal("incorrect filtering")
	}
	loaded, err := NewStore(s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Count() != 2 {
		t.Fatal("loot not restored")
	}
	item := loaded.List("file", "")[0]
	if item.Description != "first artifact" || item.Tags[0] != "lab" || item.Data != "sensitive" {
		t.Fatalf("stored data mutated: %+v", item)
	}
	data, err := loaded.Export()
	if err != nil || !json.Valid(data) {
		t.Fatalf("invalid export: %v", err)
	}
	info, err := os.Stat(filepath.Join(s.dataDir, "loot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("loot file not private")
	}
}

func TestInvalidItemsAndDuplicatesRejected(t *testing.T) {
	s := newTestStore(t)
	for _, item := range []*Item{nil, {}, {Type: "file"}, {Type: " ", Description: "description"}, {Type: "file", Description: " "}} {
		if err := s.Add(item); err == nil {
			t.Fatalf("accepted invalid item: %+v", item)
		}
	}
	item := &Item{ID: "custom-id", Type: "file", Description: "valid"}
	if err := s.Add(item); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(item); err == nil {
		t.Fatal("duplicate ID accepted")
	}
	if s.Count() != 1 {
		t.Fatal("invalid add changed state")
	}
}

func TestLoadFailuresPreserveFile(t *testing.T) {
	valid := fmt.Sprintf(`{"id":"one","type":"file","description":"valid","created_at":%q}`, time.Now().UTC().Format(time.RFC3339Nano))
	for _, data := range []string{"{broken", "null", "{}", "[null]", "[{}]", "[" + valid + "," + valid + "]"} {
		t.Run(data, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "loot.json")
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(dir); err == nil {
				t.Fatal("invalid loot silently accepted")
			}
			after, _ := os.ReadFile(path)
			if string(after) != data {
				t.Fatal("invalid store rewritten")
			}
		})
	}
}

func TestWriteFailureDoesNotMutateMemoryOrDisk(t *testing.T) {
	s := newTestStore(t)
	if err := s.Add(&Item{Type: "file", Description: "original"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(s.dataDir, "loot.json"))
	s.writeFile = func(*os.Root, string, []byte) error { return errors.New("injected failure") }
	item := &Item{Type: "file", Description: "new"}
	if err := s.Add(item); err == nil {
		t.Fatal("save failure ignored")
	}
	if item.ID != "" || !item.CreatedAt.IsZero() {
		t.Fatal("failed save changed caller metadata")
	}
	after, _ := os.ReadFile(filepath.Join(s.dataDir, "loot.json"))
	if s.Count() != 1 || !bytes.Equal(before, after) {
		t.Fatal("failed write changed store")
	}
	reopened, err := NewStore(s.dataDir)
	if err != nil || reopened.Count() != 1 {
		t.Fatalf("old store not recoverable: %v", err)
	}
}

func TestCommittedWarningKeepsMemoryInSync(t *testing.T) {
	s := newTestStore(t)
	s.writeFile = func(root *os.Root, name string, data []byte) error {
		if err := storage.WriteFileInRoot(root, name, data); err != nil {
			return err
		}
		return &storage.DurabilityError{Err: errors.New("injected sync failure")}
	}
	item := &Item{Type: "file", Description: "committed"}
	if err := s.Add(item); !storage.Committed(err) {
		t.Fatalf("missing durability warning: %v", err)
	}
	if s.Count() != 1 || item.ID == "" {
		t.Fatal("committed data rolled back")
	}
	reopened, err := NewStore(s.dataDir)
	if err != nil || reopened.Count() != 1 {
		t.Fatalf("committed data absent: %v", err)
	}
}

func TestConcurrentAddsAndReaders(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			if err := s.Add(&Item{Type: "file", Description: fmt.Sprintf("artifact %d", i), Tags: []string{"tag"}}); err != nil {
				t.Error(err)
			}
			for _, item := range s.List("", "") {
				item.Tags[0] = "caller-owned"
			}
			_, _ = s.Export()
		})
	}
	wg.Wait()
	reopened, err := NewStore(s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Count() != 16 {
		t.Fatal("concurrent writes lost items")
	}
	for _, item := range s.List("", "") {
		if item.Tags[0] != "tag" {
			t.Fatal("returned slice aliased store")
		}
	}
}

func TestSymlinkedLootFileRejected(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "loot.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewStore(dir); err == nil {
		t.Fatal("symlinked store accepted")
	}
}

func TestOversizedStoreRejectedBeforeReading(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loot.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxStoreBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir); err == nil {
		t.Fatal("oversized loot accepted")
	}
}

func TestLegacyIDsRemainReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loot.json")
	data := []byte(`[{"id":"loot_1700000000000000000","type":"hash","description":"legacy","created_at":"2023-11-14T00:00:00Z"}]`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 1 || s.List("", "")[0].ID != "loot_1700000000000000000" {
		t.Fatal("legacy ID lost")
	}
}
