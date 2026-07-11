package credstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")

	s, err := NewStore(path, "testpass")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("new store should be empty, got %d", s.Count())
	}
}

func TestAdd_And_Count(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")

	s, _ := NewStore(path, "pass")
	if err := s.Add(&Entry{Host: "10.0.0.1", Username: "admin", Secret: "pw", Type: "password", Source: "brute"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("count = %d, want 1", s.Count())
	}
}

func TestAdd_AutoID(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "c.enc"), "p")

	e := &Entry{Host: "h", Username: "u", Secret: "s", Type: "t", Source: "src"}
	_ = s.Add(e)
	if e.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestPersistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")

	s1, _ := NewStore(path, "mykey")
	_ = s1.Add(&Entry{Host: "10.0.0.1", Username: "root", Secret: "toor", Type: "password", Source: "manual", Valid: true})
	_ = s1.Add(&Entry{Host: "10.0.0.2", Username: "admin", Secret: "admin", Type: "password", Source: "spray", Valid: false})

	s2, err := NewStore(path, "mykey")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s2.Count() != 2 {
		t.Errorf("count after reload = %d, want 2", s2.Count())
	}
}

func TestPersistence_WrongKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")

	s1, _ := NewStore(path, "correct")
	_ = s1.Add(&Entry{Host: "h", Username: "u", Secret: "s", Type: "t", Source: "x"})

	_, err := NewStore(path, "wrong")
	if err == nil {
		t.Fatal("opening with wrong key should fail")
	}
}

func TestPersistence_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.enc")

	_ = os.WriteFile(path, []byte("garbage data"), 0600)

	_, err := NewStore(path, "anykey")
	if err == nil {
		t.Fatal("corrupt file should fail")
	}
}

func TestSearch(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "c.enc"), "k")
	_ = s.Add(&Entry{Host: "web.corp.local", Username: "admin", Secret: "x", Type: "password", Domain: "CORP", Source: "kerberoast"})
	_ = s.Add(&Entry{Host: "db.corp.local", Username: "sa", Secret: "y", Type: "password", Domain: "CORP", Source: "manual"})
	_ = s.Add(&Entry{Host: "10.0.0.5", Username: "root", Secret: "z", Type: "ssh_key", Source: "loot"})

	tests := []struct {
		query string
		want  int
	}{
		{"corp", 2},
		{"admin", 1},
		{"root", 1},
		{"kerberoast", 1},
		{"nonexistent", 0},
	}
	for _, tc := range tests {
		got := s.Search(tc.query)
		if len(got) != tc.want {
			t.Errorf("Search(%q) = %d, want %d", tc.query, len(got), tc.want)
		}
	}
}

func TestListByHost(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "c.enc"), "k")
	_ = s.Add(&Entry{Host: "10.0.0.1", Username: "a", Secret: "x", Type: "t", Source: "s"})
	_ = s.Add(&Entry{Host: "10.0.0.1", Username: "b", Secret: "y", Type: "t", Source: "s"})
	_ = s.Add(&Entry{Host: "10.0.0.2", Username: "c", Secret: "z", Type: "t", Source: "s"})

	got := s.ListByHost("10.0.0.1")
	if len(got) != 2 {
		t.Errorf("ListByHost = %d, want 2", len(got))
	}
}

func TestValidOnly(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "c.enc"), "k")
	_ = s.Add(&Entry{Host: "h", Username: "a", Secret: "x", Type: "t", Source: "s", Valid: true})
	_ = s.Add(&Entry{Host: "h", Username: "b", Secret: "y", Type: "t", Source: "s", Valid: false})
	_ = s.Add(&Entry{Host: "h", Username: "c", Secret: "z", Type: "t", Source: "s", Valid: true})

	got := s.ValidOnly()
	if len(got) != 2 {
		t.Errorf("ValidOnly = %d, want 2", len(got))
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := deriveKey("testpass")
	plaintext := []byte("sensitive credential data")

	encrypted, err := encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(encrypted) == string(plaintext) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := deriveKey("key1")
	key2 := deriveKey("key2")

	encrypted, _ := encrypt([]byte("secret"), key1)
	_, err := decrypt(encrypted, key2)
	if err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := deriveKey("k")
	_, err := decrypt([]byte("short"), key)
	if err == nil {
		t.Fatal("decrypt of too-short data should fail")
	}
}
