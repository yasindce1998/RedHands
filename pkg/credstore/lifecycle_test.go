package credstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyUpgradeAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.enc")
	legacy, err := encrypt([]byte(`[{"id":"one","username":"u","secret":"secret","type":"password"}]`), deriveKey("old-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path, "old-pass")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, legacy) {
		t.Fatal("opening legacy store modified it")
	}
	if err := s.Upgrade(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.Contains(data, []byte(`"version":1`)) || bytes.Contains(data, []byte("secret")) {
		t.Fatalf("invalid encrypted envelope: %s", data)
	}
	if _, err := NewStore(path, "old-pass"); err != nil {
		t.Fatal(err)
	}
	newKey := "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if err := s.RotateKey(newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, "old-pass"); err == nil {
		t.Fatal("old key still accepted")
	}
	reopened, err := NewStore(path, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Search("")[0].Secret != "secret" {
		t.Fatal("rotation lost secret")
	}
}

func TestSaltAndInvalidRawKey(t *testing.T) {
	a, err := NewStore(filepath.Join(t.TempDir(), "a.enc"), "same-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStore(filepath.Join(t.TempDir(), "b.enc"), "same-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.key, b.key) {
		t.Fatal("same passphrase produced unsalted keys")
	}
	if _, err := NewStore(filepath.Join(t.TempDir(), "bad.enc"), "hex:short"); err == nil {
		t.Fatal("invalid raw key accepted")
	}
}

func TestRotationFailureKeepsOldStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")
	key := "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	s, err := NewStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(&Entry{Username: "u", Secret: "secret", Type: "password"}); err != nil {
		t.Fatal(err)
	}
	previousKey := append([]byte(nil), s.key...)
	s.file = filepath.Join(dir, "missing", "creds.enc")
	if err := s.RotateKey("hex:010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); err == nil {
		t.Fatal("rotation unexpectedly succeeded")
	}
	if !bytes.Equal(previousKey, s.key) {
		t.Fatal("failed rotation changed in-memory key")
	}
	if _, err := NewStore(path, key); err != nil {
		t.Fatal("old file no longer readable")
	}
}
