package evidence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Item struct {
	ID        string    `json:"id"`
	Tool      string    `json:"tool"`
	Host      string    `json:"host"`
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Notes     string    `json:"notes,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	dir     string
	items   []*Item
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create evidence dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) SaveOutput(tool, host, output string) (*Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	filename := fmt.Sprintf("%s_%s_%s.txt", tool, host, id[:8])
	path := filepath.Join(s.dir, filename)

	if err := os.WriteFile(path, []byte(output), 0600); err != nil {
		return nil, fmt.Errorf("write evidence: %w", err)
	}

	item := &Item{
		ID:        id,
		Tool:      tool,
		Host:      host,
		Type:      "output",
		Path:      path,
		Timestamp: time.Now(),
	}
	s.items = append(s.items, item)
	return item, nil
}

func (s *Store) Screenshot(ctx context.Context, url string) (*Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	filename := fmt.Sprintf("screenshot_%s.png", id[:8])
	path := filepath.Join(s.dir, filename)

	cmd := exec.CommandContext(ctx, "cutycapt",
		"--url="+url,
		"--out="+path,
		"--min-width=1280",
		"--delay=2000",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cutycapt: %s: %w", string(output), err)
	}

	item := &Item{
		ID:        id,
		Tool:      "cutycapt",
		Host:      url,
		Type:      "screenshot",
		Path:      path,
		Timestamp: time.Now(),
	}
	s.items = append(s.items, item)
	return item, nil
}

func (s *Store) SaveFile(tool, host string, data []byte, ext string) (*Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	filename := fmt.Sprintf("%s_%s_%s%s", tool, host, id[:8], ext)
	path := filepath.Join(s.dir, filename)

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write evidence file: %w", err)
	}

	item := &Item{
		ID:        id,
		Tool:      tool,
		Host:      host,
		Type:      "file",
		Path:      path,
		Timestamp: time.Now(),
	}
	s.items = append(s.items, item)
	return item, nil
}

func (s *Store) List() []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Item, len(s.items))
	copy(result, s.items)
	return result
}

func (s *Store) ListByTool(tool string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Item
	for _, item := range s.items {
		if item.Tool == tool {
			result = append(result, item)
		}
	}
	return result
}

func (s *Store) ListByHost(host string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Item
	for _, item := range s.items {
		if item.Host == host {
			result = append(result, item)
		}
	}
	return result
}

func (s *Store) Dir() string {
	return s.dir
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
