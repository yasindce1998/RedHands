package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/redhands/pkg/credstore"
)

func TestMigrationPreservesDataAndVerifiesEncryptedSecrets(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "targetdb.json")
	encrypted := filepath.Join(dir, "creds.enc")
	t.Setenv("REDHANDS_TARGETDB_FILE", db)
	t.Setenv("REDHANDS_CREDSTORE_FILE", encrypted)
	t.Setenv("REDHANDS_CREDSTORE_KEY", "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data := []byte(`{"unknown":{"keep":123},"hosts":{},"credentials":[{"id":"one","username":"admin","secret":"private-value","type":"password","custom":"preserve"}]}`)
	if err := os.WriteFile(db, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"migrate-targetdb"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("private-value")) || !bytes.Contains(got, []byte("preserve")) || !bytes.Contains(got, []byte("unknown")) {
		t.Fatalf("migration data invalid: %s", got)
	}
	s, err := credstore.NewStore(encrypted, os.Getenv("REDHANDS_CREDSTORE_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Search("")[0].Secret != "private-value" {
		t.Fatal("secret lost")
	}
	if err := run([]string{"migrate-targetdb"}); err != nil {
		t.Fatal(err)
	}
	if s.Count() != 1 {
		t.Fatal("migration not idempotent")
	}
	if err := run([]string{"verify"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDHANDS_CREDSTORE_NEW_KEY", "hex:010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err := run([]string{"rotate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := credstore.NewStore(encrypted, os.Getenv("REDHANDS_CREDSTORE_KEY")); err == nil {
		t.Fatal("old key still works")
	}
}

func TestFailedMigrationLeavesSourceUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targetdb.json")
	t.Setenv("REDHANDS_TARGETDB_FILE", path)
	t.Setenv("REDHANDS_CREDSTORE_FILE", filepath.Join(dir, "creds.enc"))
	t.Setenv("REDHANDS_CREDSTORE_KEY", "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data := []byte(`{"credentials":[{"secret":"value"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"migrate-targetdb"}); err == nil {
		t.Fatal("invalid metadata accepted")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, data) {
		t.Fatal("failed migration changed source")
	}
	if !json.Valid(got) {
		t.Fatal("source corrupted")
	}
}

func TestConflictingCredentialsAreNotSilentlyMerged(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "targetdb.json")
	store := filepath.Join(dir, "creds.enc")
	t.Setenv("REDHANDS_TARGETDB_FILE", db)
	t.Setenv("REDHANDS_CREDSTORE_FILE", store)
	t.Setenv("REDHANDS_CREDSTORE_KEY", "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data := []byte(`{"credentials":[{"username":"u","type":"password","secret":"one"},{"username":"u","type":"password","secret":"two"}]}`)
	if err := os.WriteFile(db, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"migrate-targetdb"}); err == nil {
		t.Fatal("conflicting secrets merged")
	}
	got, _ := os.ReadFile(db)
	if !bytes.Equal(got, data) {
		t.Fatal("source changed")
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatal("invalid import wrote encrypted destination")
	}
}
