package credstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/yasindce1998/redhands/pkg/storage"
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
	mu       sync.RWMutex
	entries  []*Entry
	key      []byte
	file     string
	envelope envelope
}

const passphraseIterations = 600000
const envelopeMagic = "REDHANDS-CREDS\n"

type envelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       []byte `json:"salt,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Data       []byte `json:"data"`
}

func NewStore(file string, passphrase string) (*Store, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, fmt.Errorf("credential store key must not be empty")
	}
	s := &Store{
		file: file,
	}
	if err := s.load(passphrase); err != nil {
		return nil, fmt.Errorf("credstore load: %w", err)
	}
	return s, nil
}

func newEnvelopeKey(passphrase string) (envelope, []byte, error) {
	e := envelope{Version: 1}
	if strings.HasPrefix(passphrase, "hex:") {
		e.KDF = "raw-aes256"
		key, err := hex.DecodeString(strings.TrimPrefix(passphrase, "hex:"))
		if err != nil || len(key) != 32 {
			return e, nil, fmt.Errorf("hex: credential key must contain exactly 32 random bytes")
		}
		return e, key, nil
	}
	e.KDF = "pbkdf2-sha256"
	e.Iterations = passphraseIterations
	e.Salt = make([]byte, 16)
	if _, err := rand.Read(e.Salt); err != nil {
		return e, nil, err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, e.Salt, e.Iterations, 32)
	return e, key, err
}

// Upgrade explicitly rewrites a successfully opened legacy store in the current
// versioned format. Merely opening a legacy store never changes its bytes.
func (s *Store) Upgrade() error { s.mu.Lock(); defer s.mu.Unlock(); return s.save() }

// RotateKey atomically re-encrypts the store. The previous key remains active if
// preparation or replacement fails. A post-replacement durability warning keeps
// the new in-memory key, matching the replaced file. Back up before rotation.
func (s *Store) RotateKey(passphrase string) error {
	if strings.TrimSpace(passphrase) == "" {
		return fmt.Errorf("credential store key must not be empty")
	}
	e, key, err := newEnvelopeKey(passphrase)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldEnvelope, oldKey := s.envelope, s.key
	s.envelope, s.key = e, key
	if err := s.save(); err != nil {
		if !storage.Committed(err) {
			s.envelope, s.key = oldEnvelope, oldKey
		}
		return err
	}
	return nil
}

func (s *Store) Add(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.ID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		e.ID = hex.EncodeToString(b)
	}
	copyEntry := *e
	for i, old := range s.entries {
		if old.ID == e.ID || (old.Host == e.Host && old.Username == e.Username && old.Domain == e.Domain && old.Type == e.Type) {
			if old.ID == e.ID && (old.Host != e.Host || old.Username != e.Username || old.Domain != e.Domain || old.Type != e.Type) {
				return fmt.Errorf("credential ID conflicts with another identity")
			}
			copyEntry.ID = old.ID
			s.entries[i] = &copyEntry
			if err := s.save(); err != nil {
				if !storage.Committed(err) {
					s.entries[i] = old
				}
				return err
			}
			e.ID = copyEntry.ID
			return nil
		}
	}
	s.entries = append(s.entries, &copyEntry)
	if err := s.save(); err != nil {
		if !storage.Committed(err) {
			s.entries = s.entries[:len(s.entries)-1]
		}
		return err
	}
	return nil
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
			copyEntry := *e
			results = append(results, &copyEntry)
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
			copyEntry := *e
			results = append(results, &copyEntry)
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
			copyEntry := *e
			results = append(results, &copyEntry)
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
	e := s.envelope
	e.Data = encrypted
	encoded, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return storage.WriteFile(s.file, append([]byte(envelopeMagic), encoded...))
}

func (s *Store) load(passphrase string) error {
	data, err := os.ReadFile(s.file)
	if err != nil {
		if os.IsNotExist(err) {
			s.envelope, s.key, err = newEnvelopeKey(passphrase)
			return err
		}
		return err
	}
	legacy := !bytes.HasPrefix(data, []byte(envelopeMagic))
	if legacy {
		s.key = deriveKey(passphrase)
	} else {
		if err := json.Unmarshal(bytes.TrimPrefix(data, []byte(envelopeMagic)), &s.envelope); err != nil {
			return err
		}
		if s.envelope.Version != 1 {
			return fmt.Errorf("unsupported credential store version")
		}
		switch s.envelope.KDF {
		case "pbkdf2-sha256":
			if len(s.envelope.Salt) != 16 || s.envelope.Iterations != passphraseIterations {
				return fmt.Errorf("unsupported credential KDF parameters")
			}
			s.key, err = pbkdf2.Key(sha256.New, passphrase, s.envelope.Salt, s.envelope.Iterations, 32)
			if err != nil {
				return err
			}
		case "raw-aes256":
			if !strings.HasPrefix(passphrase, "hex:") {
				return fmt.Errorf("store requires a hex: encryption key")
			}
			_, s.key, err = newEnvelopeKey(passphrase)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported credential KDF")
		}
		data = s.envelope.Data
	}
	decrypted, err := decrypt(data, s.key)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	if err := json.Unmarshal(decrypted, &s.entries); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	for _, entry := range s.entries {
		if entry == nil {
			return fmt.Errorf("invalid null credential record")
		}
	}
	if legacy {
		s.envelope, s.key, err = newEnvelopeKey(passphrase)
		if err != nil {
			return err
		}
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
