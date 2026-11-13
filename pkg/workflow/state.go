package workflow

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// StateManager handles workflow checkpointing and resume.
type StateManager struct {
	dir string
	mu  sync.RWMutex
}

// NewStateManager creates a state manager with the given directory.
func NewStateManager(dir string) *StateManager {
	return &StateManager{dir: dir}
}

// Dir returns the state directory. The engine uses it to place per-campaign
// run locks next to the checkpoint files they protect.
func (sm *StateManager) Dir() string {
	return sm.dir
}

// ValidWorkflowID rejects IDs that could escape the state directory.
func ValidWorkflowID(id string) error {
	if id == "" {
		return fmt.Errorf("workflow id is required")
	}
	if len(id) > 64 {
		return fmt.Errorf("workflow id too long (max 64 chars)")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("workflow id %q contains unsupported characters (allowed: letters, digits, underscore, dash)", id)
		}
	}
	return nil
}

// Save persists workflow state to disk.
func (sm *StateManager) Save(state *State) error {
	if err := ValidWorkflowID(state.WorkflowID); err != nil {
		return err
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if err := os.MkdirAll(sm.dir, 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	path := filepath.Join(sm.dir, state.WorkflowID+".json")
	return os.WriteFile(path, data, 0600)
}

// Load reads workflow state from disk.
func (sm *StateManager) Load(workflowID string) (*State, error) {
	if err := ValidWorkflowID(workflowID); err != nil {
		return nil, err
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	path := filepath.Join(sm.dir, workflowID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &state, nil
}

// List returns all saved workflow states.
func (sm *StateManager) List() ([]*State, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	entries, err := os.ReadDir(sm.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var states []*State
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sm.dir, entry.Name()))
		if err != nil {
			continue
		}
		var s State
		if json.Unmarshal(data, &s) == nil {
			states = append(states, &s)
		}
	}
	return states, nil
}

// Delete removes a workflow state file.
func (sm *StateManager) Delete(workflowID string) error {
	if err := ValidWorkflowID(workflowID); err != nil {
		return err
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	path := filepath.Join(sm.dir, workflowID+".json")
	return os.Remove(path)
}

// GenerateID creates a random workflow ID.
func GenerateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
