package mcp

import "context"

// ToolPolicy is a server-owned description of the entire tool interface, not a
// client's claim about one invocation. Mixed read/write tools are conservative.
type ToolPolicy struct {
	ReadOnly           bool `json:"readOnly"`
	NetworkAccess      bool `json:"networkAccess"`
	RequiresPrivileges bool `json:"requiresPrivileges"`
	RequiresApproval   bool `json:"requiresApproval"`
	RetrySafe          bool `json:"retrySafe"`
	Cacheable          bool `json:"cacheable"`
}

// Unknown tools and plugins cannot opt themselves into trusted execution or caching.
func ConservativePolicy() ToolPolicy {
	return ToolPolicy{NetworkAccess: true, RequiresPrivileges: true, RequiresApproval: true}
}

func (s *Server) SetToolPolicy(name string, policy ToolPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tools[name]; ok {
		s.policies[name] = policy
	}
}

func (s *Server) ToolPolicy(name string) ToolPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.policies[name]; ok {
		return p
	}
	return ConservativePolicy()
}

type toolPolicyContextKey struct{}

// PolicyFromContext returns the policy captured with the executing tool. This
// avoids re-reading registry metadata while plugins may be replaced concurrently.
func PolicyFromContext(ctx context.Context) ToolPolicy {
	if p, ok := ctx.Value(toolPolicyContextKey{}).(ToolPolicy); ok {
		return p
	}
	return ConservativePolicy()
}
