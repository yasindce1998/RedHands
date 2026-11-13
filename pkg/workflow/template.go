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
// The caller's vars map is never modified: defaults are applied to a copy.
func (tm *TemplateManager) Instantiate(name string, vars map[string]string) (*EnhancedWorkflowRequest, error) {
	t, ok := tm.Get(name)
	if !ok {
		return nil, fmt.Errorf("template %q not found", name)
	}

	// Work on a copy so required-variable checks and defaults do not leak
	// back into the caller's map (which may be shared across requests).
	resolved := make(map[string]string, len(vars)+len(t.Vars))
	for k, v := range vars {
		resolved[k] = v
	}

	for _, v := range t.Vars {
		if v.Required {
			if _, ok := resolved[v.Name]; !ok {
				if v.Default != "" {
					resolved[v.Name] = v.Default
				} else {
					return nil, fmt.Errorf("required variable %q not provided", v.Name)
				}
			}
		}
	}

	// Apply defaults for non-required vars
	for _, v := range t.Vars {
		if _, ok := resolved[v.Name]; !ok && v.Default != "" {
			resolved[v.Name] = v.Default
		}
	}

	// Serialize steps to JSON, substitute, and deserialize
	data, err := json.Marshal(t.Steps)
	if err != nil {
		return nil, fmt.Errorf("marshal steps: %w", err)
	}

	s := string(data)
	for k, v := range resolved {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}

	var steps []EnhancedStep
	if err := json.Unmarshal([]byte(s), &steps); err != nil {
		return nil, fmt.Errorf("instantiate steps: %w", err)
	}

	return &EnhancedWorkflowRequest{
		Name:  name,
		Steps: steps,
		Vars:  resolved,
	}, nil
}

// Save persists a template to the template directory. Template names become
// filenames, so they are restricted to a conservative identifier set.
func (tm *TemplateManager) Save(t *Template) error {
	if t.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if len(t.Name) > 64 {
		return fmt.Errorf("template name too long (max 64 chars)")
	}
	for _, r := range t.Name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("template name %q contains unsupported characters (allowed: letters, digits, underscore, dash)", t.Name)
		}
	}
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
