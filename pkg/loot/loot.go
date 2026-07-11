package loot

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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
	mu      sync.RWMutex
	items   []*Item
	dataDir string
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("loot: create dir: %w", err)
	}
	s := &Store{dataDir: dataDir}
	s.load()
	return s, nil
}

func (s *Store) Add(item *Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if item.ID == "" {
		item.ID = fmt.Sprintf("loot_%d", time.Now().UnixNano())
	}
	item.CreatedAt = time.Now()
	s.items = append(s.items, item)
	return s.save()
}

func (s *Store) List(lootType, host string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Item
	for _, item := range s.items {
		if lootType != "" && item.Type != lootType {
			continue
		}
		if host != "" && item.Host != host {
			continue
		}
		result = append(result, item)
	}
	return result
}

func (s *Store) Search(query string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(query)
	var result []*Item
	for _, item := range s.items {
		if strings.Contains(strings.ToLower(item.Description), q) ||
			strings.Contains(strings.ToLower(item.Data), q) ||
			strings.Contains(strings.ToLower(item.Host), q) {
			result = append(result, item)
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

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dataDir, "loot.json"), b, 0600)
}

func (s *Store) load() {
	b, err := os.ReadFile(filepath.Join(s.dataDir, "loot.json"))
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &s.items); err != nil {
		log.Printf("loot: failed to parse loot.json: %v", err)
	}
}
