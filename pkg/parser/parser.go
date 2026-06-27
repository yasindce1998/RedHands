package parser

import "encoding/json"

// Parser interface for structured tool output parsing.
type Parser interface {
	// Name returns the parser identifier (e.g., "nmap_xml", "nuclei_json").
	Name() string
	// Parse takes raw tool output and returns structured data.
	Parse(data []byte) (json.RawMessage, error)
}

// Registry holds available parsers.
type Registry struct {
	parsers map[string]Parser
}

// NewRegistry creates a parser registry with built-in parsers.
func NewRegistry() *Registry {
	r := &Registry{parsers: make(map[string]Parser)}
	r.Register(&NmapXMLParser{})
	r.Register(&NucleiJSONParser{})
	r.Register(&MasscanJSONParser{})
	return r
}

// Register adds a parser to the registry.
func (r *Registry) Register(p Parser) {
	r.parsers[p.Name()] = p
}

// Get returns a parser by name.
func (r *Registry) Get(name string) (Parser, bool) {
	p, ok := r.parsers[name]
	return p, ok
}

// List returns all registered parser names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		names = append(names, name)
	}
	return names
}
