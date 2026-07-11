package engagement

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Engagement struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Client    string    `json:"client,omitempty"`
	Scope     []string  `json:"scope"`
	StartDate string    `json:"start_date"`
	EndDate   string    `json:"end_date,omitempty"`
	Status    string    `json:"status"`
	DataDir   string    `json:"data_dir"`
	CreatedAt time.Time `json:"created_at"`
}

type Manager struct {
	mu          sync.RWMutex
	engagements map[string]*Engagement
	active      string
	baseDir     string
}

func NewManager(baseDir string) *Manager {
	m := &Manager{
		engagements: make(map[string]*Engagement),
		baseDir:     baseDir,
	}
	m.load()
	return m
}

func (m *Manager) Create(name, client string, scope []string) (*Engagement, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range m.engagements {
		if e.Name == name {
			return nil, fmt.Errorf("engagement %q already exists", name)
		}
	}

	id := fmt.Sprintf("eng_%d", time.Now().UnixNano())
	dataDir := filepath.Join(m.baseDir, id)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	eng := &Engagement{
		ID:        id,
		Name:      name,
		Client:    client,
		Scope:     scope,
		StartDate: time.Now().Format("2006-01-02"),
		Status:    "active",
		DataDir:   dataDir,
		CreatedAt: time.Now(),
	}

	m.engagements[id] = eng
	if m.active == "" {
		m.active = id
	}
	if err := m.save(); err != nil {
		return nil, fmt.Errorf("save engagement: %w", err)
	}
	return eng, nil
}

func (m *Manager) Switch(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.engagements[id]; !ok {
		return fmt.Errorf("engagement %q not found", id)
	}
	m.active = id
	return m.save()
}

func (m *Manager) Active() *Engagement {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engagements[m.active]
}

func (m *Manager) List() []*Engagement {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Engagement, 0, len(m.engagements))
	for _, e := range m.engagements {
		result = append(result, e)
	}
	return result
}

func (m *Manager) InScope(target string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	eng := m.engagements[m.active]
	if eng == nil || len(eng.Scope) == 0 {
		return true
	}

	for _, s := range eng.Scope {
		if matchScope(target, s) {
			return true
		}
	}
	return false
}

func matchScope(target, scope string) bool {
	if target == scope {
		return true
	}
	matched, _ := filepath.Match(scope, target)
	return matched
}

func (m *Manager) save() error {
	data := struct {
		Engagements map[string]*Engagement `json:"engagements"`
		Active      string                 `json:"active"`
	}{m.engagements, m.active}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.baseDir, "engagements.json"), b, 0600)
}

func (m *Manager) load() {
	b, err := os.ReadFile(filepath.Join(m.baseDir, "engagements.json"))
	if err != nil {
		return
	}
	var data struct {
		Engagements map[string]*Engagement `json:"engagements"`
		Active      string                 `json:"active"`
	}
	if json.Unmarshal(b, &data) == nil && data.Engagements != nil {
		m.engagements = data.Engagements
		m.active = data.Active
	}
}
