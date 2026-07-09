package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TemplateManager loads and instantiates workflow templates.
type TemplateManager struct {
	dir       string
	mu        sync.RWMutex
	templates map[string]*Template
}

// NewTemplateManager creates a template manager scanning the given directory.
func NewTemplateManager(dir string) *TemplateManager {
	tm := &TemplateManager{
		dir:       dir,
		templates: make(map[string]*Template),
	}
	tm.Reload()
	return tm
}

// Reload scans the template directory and loads all templates.
func (tm *TemplateManager) Reload() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	entries, err := os.ReadDir(tm.dir)
	if err != nil {
		return
	}

	templates := make(map[string]*Template)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tm.dir, entry.Name()))
		if err != nil {
			continue
		}
		var t Template
		if json.Unmarshal(data, &t) == nil && t.Name != "" {
			templates[t.Name] = &t
		}
	}
	tm.templates = templates
}

// Get returns a template by name.
func (tm *TemplateManager) Get(name string) (*Template, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, ok := tm.templates[name]
	return t, ok
}

// List returns all available templates.
func (tm *TemplateManager) List() []*Template {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	result := make([]*Template, 0, len(tm.templates))
	for _, t := range tm.templates {
		result = append(result, t)
	}
	return result
}

// Instantiate creates a workflow request from a template with variable substitution.
func (tm *TemplateManager) Instantiate(name string, vars map[string]string) (*EnhancedWorkflowRequest, error) {
	t, ok := tm.Get(name)
	if !ok {
		return nil, fmt.Errorf("template %q not found", name)
	}

	for _, v := range t.Vars {
		if v.Required {
			if _, ok := vars[v.Name]; !ok {
				if v.Default != "" {
					vars[v.Name] = v.Default
				} else {
					return nil, fmt.Errorf("required variable %q not provided", v.Name)
				}
			}
		}
	}

	// Apply defaults for non-required vars
	for _, v := range t.Vars {
		if _, ok := vars[v.Name]; !ok && v.Default != "" {
			vars[v.Name] = v.Default
		}
	}

	// Serialize steps to JSON, substitute, and deserialize
	data, err := json.Marshal(t.Steps)
	if err != nil {
		return nil, fmt.Errorf("marshal steps: %w", err)
	}

	s := string(data)
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}

	var steps []EnhancedStep
	if err := json.Unmarshal([]byte(s), &steps); err != nil {
		return nil, fmt.Errorf("instantiate steps: %w", err)
	}

	return &EnhancedWorkflowRequest{
		Name:  name,
		Steps: steps,
		Vars:  vars,
	}, nil
}

// Save persists a template to the template directory.
func (tm *TemplateManager) Save(t *Template) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if err := os.MkdirAll(tm.dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(tm.dir, t.Name+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}

	tm.templates[t.Name] = t
	return nil
}
