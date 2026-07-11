package credstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Entry struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Type     string `json:"type"`
	Domain   string `json:"domain,omitempty"`
	Source   string `json:"source"`
	Notes    string `json:"notes,omitempty"`
	Valid    bool   `json:"valid"`
}

type Store struct {
	mu      sync.RWMutex
	entries []*Entry
	key     []byte
	file    string
}

func NewStore(file string, passphrase string) (*Store, error) {
	key := deriveKey(passphrase)
	s := &Store{
		key:  key,
		file: file,
	}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("credstore load: %w", err)
	}
	return s, nil
}

func (s *Store) Add(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.ID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		e.ID = hex.EncodeToString(b)
	}
	s.entries = append(s.entries, e)
	return s.save()
}

func (s *Store) Search(query string) []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(query)
	var results []*Entry
	for _, e := range s.entries {
		if strings.Contains(strings.ToLower(e.Host), q) ||
			strings.Contains(strings.ToLower(e.Username), q) ||
			strings.Contains(strings.ToLower(e.Domain), q) ||
			strings.Contains(strings.ToLower(e.Source), q) {
			results = append(results, e)
		}
	}
	return results
}

func (s *Store) ListByHost(host string) []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Entry
	for _, e := range s.entries {
		if e.Host == host {
			results = append(results, e)
		}
	}
	return results
}

func (s *Store) ValidOnly() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Entry
	for _, e := range s.entries {
		if e.Valid {
			results = append(results, e)
		}
	}
	return results
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *Store) save() error {
	data, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	encrypted, err := encrypt(data, s.key)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return os.WriteFile(s.file, encrypted, 0600)
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	decrypted, err := decrypt(data, s.key)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := json.Unmarshal(decrypted, &s.entries); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

func deriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
