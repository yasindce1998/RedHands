package targetdb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

type Store struct {
	mu          sync.RWMutex
	hosts       map[string]*Host
	services    map[string][]*Service
	credentials []*Credential
	findings    []*Finding
	filePath    string
	autoSave    bool
}

func NewStore(filePath string, autoSave bool) *Store {
	s := &Store{
		hosts:    make(map[string]*Host),
		services: make(map[string][]*Service),
		filePath: filePath,
		autoSave: autoSave,
	}
	if filePath != "" {
		if err := s.Load(); err != nil {
			log.Printf("targetdb: failed to load %s: %v", filePath, err)
		}
	}
	return s
}

func (s *Store) AddHost(h *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if existing, ok := s.hosts[h.IP]; ok {
		existing.LastSeen = now
		if h.Hostname != "" {
			existing.Hostname = h.Hostname
		}
		if h.OS != "" {
			existing.OS = h.OS
		}
		if h.Tags != nil {
			existing.Tags = mergeTags(existing.Tags, h.Tags)
		}
		if h.Meta != nil {
			if existing.Meta == nil {
				existing.Meta = make(map[string]string)
			}
			for k, v := range h.Meta {
				existing.Meta[k] = v
			}
		}
	} else {
		h.FirstSeen = now
		h.LastSeen = now
		s.hosts[h.IP] = h
	}

	if s.autoSave {
		return s.save()
	}
	return nil
}

func (s *Store) GetHost(ip string) (*Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[ip]
	return h, ok
}

func (s *Store) ListHosts() []*Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]*Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, h)
	}
	return hosts
}

func (s *Store) AddService(svc *Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := svc.Host
	for _, existing := range s.services[key] {
		if existing.Port == svc.Port && existing.Protocol == svc.Protocol {
			if svc.Name != "" {
				existing.Name = svc.Name
			}
			if svc.Version != "" {
				existing.Version = svc.Version
			}
			if svc.Banner != "" {
				existing.Banner = svc.Banner
			}
			if s.autoSave {
				return s.save()
			}
			return nil
		}
	}
	s.services[key] = append(s.services[key], svc)

	if s.autoSave {
		return s.save()
	}
	return nil
}

func (s *Store) ListServices(host string) []*Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if host == "" {
		var all []*Service
		for _, svcs := range s.services {
			all = append(all, svcs...)
		}
		return all
	}
	return s.services[host]
}

func (s *Store) AddCredential(c *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.ID == "" {
		c.ID = generateID()
	}
	for _, existing := range s.credentials {
		if existing.Username == c.Username && existing.Host == c.Host && existing.Type == c.Type && existing.Domain == c.Domain {
			existing.Secret = c.Secret
			existing.Source = c.Source
			existing.Valid = c.Valid
			if s.autoSave {
				return s.save()
			}
			return nil
		}
	}
	s.credentials = append(s.credentials, c)

	if s.autoSave {
		return s.save()
	}
	return nil
}

func (s *Store) ListCredentials() []*Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Credential, len(s.credentials))
	copy(result, s.credentials)
	return result
}

func (s *Store) AddFinding(f *Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if f.ID == "" {
		f.ID = generateID()
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
	s.findings = append(s.findings, f)

	if s.autoSave {
		return s.save()
	}
	return nil
}

func (s *Store) ListFindings() []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Finding, len(s.findings))
	copy(result, s.findings)
	return result
}

func (s *Store) QueryFindings(host, severity, tool string) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*Finding
	for _, f := range s.findings {
		if host != "" && f.Host != host {
			continue
		}
		if severity != "" && f.Severity != severity {
			continue
		}
		if tool != "" && f.Tool != tool {
			continue
		}
		results = append(results, f)
	}
	return results
}

func (s *Store) Snapshot() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hosts := make(map[string]*Host, len(s.hosts))
	for k, v := range s.hosts {
		hosts[k] = v
	}
	services := make(map[string][]*Service, len(s.services))
	for k, v := range s.services {
		services[k] = v
	}
	creds := make([]*Credential, len(s.credentials))
	copy(creds, s.credentials)
	findings := make([]*Finding, len(s.findings))
	copy(findings, s.findings)

	return &Snapshot{
		Hosts:       hosts,
		Services:    services,
		Credentials: creds,
		Findings:    findings,
	}
}

func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	svcCount := 0
	for _, svcs := range s.services {
		svcCount += len(svcs)
	}
	return map[string]int{
		"hosts":       len(s.hosts),
		"services":    svcCount,
		"credentials": len(s.credentials),
		"findings":    len(s.findings),
	}
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func mergeTags(existing, new []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, t := range existing {
		seen[t] = true
	}
	for _, t := range new {
		if !seen[t] {
			existing = append(existing, t)
			seen[t] = true
		}
	}
	return existing
}
