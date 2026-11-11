package loot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/storage"
)

const maxStoreBytes = 32 * 1024 * 1024
const maxItems = 10000

type Item struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Host        string    `json:"host,omitempty"`
	Path        string    `json:"path,omitempty"`
	Description string    `json:"description"`
	Data        string    `json:"data,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Store struct {
	mu        sync.RWMutex
	items     []*Item
	dataDir   string
	writeFile func(*os.Root, string, []byte) error
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("loot: create dir: %w", err)
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	s := &Store{dataDir: abs, items: make([]*Item, 0), writeFile: storage.WriteFileInRoot}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("loot: load: %w", err)
	}
	return s, nil
}

func (s *Store) Add(item *Item) error {
	if item == nil {
		return fmt.Errorf("loot item is required")
	}
	candidateItem := cloneItem(item)
	if candidateItem.ID == "" {
		var token [16]byte
		if _, err := rand.Read(token[:]); err != nil {
			return err
		}
		candidateItem.ID = "loot_" + hex.EncodeToString(token[:])
	}
	candidateItem.CreatedAt = time.Now().UTC()
	if err := validateItem(candidateItem); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.items) >= maxItems {
		return fmt.Errorf("loot store is full")
	}
	for _, existing := range s.items {
		if existing.ID == candidateItem.ID {
			return fmt.Errorf("duplicate loot ID")
		}
	}
	candidate := append(append([]*Item(nil), s.items...), candidateItem)
	b, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > maxStoreBytes {
		return fmt.Errorf("loot store exceeds 32 MiB limit")
	}
	root, err := os.OpenRoot(s.dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	err = s.writeFile(root, "loot.json", b)
	if err != nil && !storage.Committed(err) {
		return fmt.Errorf("loot: save: %w", err)
	}
	s.items = candidate
	item.ID = candidateItem.ID
	item.CreatedAt = candidateItem.CreatedAt
	return err
}

func (s *Store) List(lootType, host string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Item, 0)
	for _, item := range s.items {
		if lootType != "" && item.Type != lootType {
			continue
		}
		if host != "" && item.Host != host {
			continue
		}
		result = append(result, cloneItem(item))
	}
	return result
}

func (s *Store) Search(query string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(query)
	result := make([]*Item, 0)
	for _, item := range s.items {
		if strings.Contains(strings.ToLower(item.Description), q) ||
			strings.Contains(strings.ToLower(item.Data), q) ||
			strings.Contains(strings.ToLower(item.Host), q) {
			result = append(result, cloneItem(item))
		}
	}
	return result
}

func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s.items, "", "  ")
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

func (s *Store) load() error {
	root, err := os.OpenRoot(s.dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	b, err := storage.ReadRegularFile(root, "loot.json", maxStoreBytes)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var items []*Item
	if err := json.Unmarshal(b, &items); err != nil {
		return err
	}
	if items == nil || len(items) > maxItems {
		return fmt.Errorf("loot.json must contain a bounded array of items")
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if err := validateItem(item); err != nil {
			return err
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicate loot ID")
		}
		seen[item.ID] = true
	}
	s.items = items
	return nil
}

func validateItem(item *Item) error {
	if item == nil || strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Type) == "" || strings.TrimSpace(item.Description) == "" || item.CreatedAt.IsZero() {
		return fmt.Errorf("loot item requires ID, type, description and timestamp")
	}
	return nil
}

func cloneItem(item *Item) *Item {
	result := *item
	result.Tags = append([]string(nil), item.Tags...)
	return &result
}
