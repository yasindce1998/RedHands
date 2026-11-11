package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
)

func TestInitStoresReturnsErrorsWithoutExiting(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Load()
	cfg.TargetDBFile = filepath.Join(dir, "db.json")
	cfg.EngagementDir = filepath.Join(dir, "engagements")
	cfg.LootDir = filepath.Join(dir, "loot")
	cfg.EvidenceDir = filepath.Join(dir, "evidence")
	cfg.CredStoreFile = filepath.Join(dir, "creds.enc")
	if err := os.WriteFile(cfg.TargetDBFile, []byte(`{"credentials":[{"secret":"legacy"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStores(&cfg); err == nil {
		t.Fatal("legacy load failure ignored")
	}
	if err := os.Remove(cfg.TargetDBFile); err != nil {
		t.Fatal(err)
	}
	cfg.CredStoreKey = "key"
	if err := os.WriteFile(cfg.CredStoreFile, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStores(&cfg); err == nil {
		t.Fatal("encrypted load failure ignored")
	}
}
