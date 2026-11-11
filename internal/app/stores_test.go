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

func TestInitStoresRejectsCorruptEvidenceAndLoot(t *testing.T) {
	for _, kind := range []string{"evidence", "loot"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Load()
			cfg.TargetDBFile = filepath.Join(dir, "targetdb.json")
			cfg.EngagementDir = filepath.Join(dir, "engagements")
			cfg.LootDir = filepath.Join(dir, "loot")
			cfg.EvidenceDir = filepath.Join(dir, "evidence")
			cfg.CredStoreKey = ""
			path := filepath.Join(cfg.EvidenceDir, "index.json")
			if kind == "loot" {
				path = filepath.Join(cfg.LootDir, "loot.json")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("{broken")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InitStores(&cfg); err == nil {
				t.Fatal("corrupt store ignored during startup")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(data) {
				t.Fatal("corrupt data changed")
			}
		})
	}
}
