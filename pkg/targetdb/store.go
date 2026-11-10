package targetdb

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/credstore"
)

type Store struct {
	mu              sync.RWMutex
	hosts           map[string]*Host
	services        map[string][]*Service
	credentials     []*Credential
	findings        []*Finding
	filePath        string
	autoSave        bool
	credentialStore *credstore.Store
	loadErr         error
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
			s.loadErr = err
			log.Printf("targetdb: failed to load %s: %v", filePath, err)
		}
	}
	return s
}

func (s *Store) LoadError() error { return s.loadErr }

func (s *Store) SetCredentialStore(store *credstore.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentialStore = store
	if store != nil {
		entries := store.Search("")
		for _, c := range s.credentials {
			for _, entry := range entries {
				if c.Host == entry.Host && c.Username == entry.Username && c.Domain == entry.Domain && c.Type == entry.Type {
					c.Secret = entry.Secret
				}
			}
		}
	}
}

func (s *Store) AddHost(h *Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h = cloneHost(h)

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
	if !ok {
		return nil, false
	}
	return cloneHost(h), true
}

func (s *Store) ListHosts() []*Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hosts := make([]*Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		hosts = append(hosts, cloneHost(h))
	}
	return hosts
}

func (s *Store) AddService(svc *Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyService := *svc
	svc = &copyService

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
			all = append(all, cloneServices(svcs)...)
		}
		return all
	}
	return cloneServices(s.services[host])
}

func (s *Store) AddCredential(c *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.filePath != "" && c.Secret != "" && s.credentialStore == nil {
		return fmt.Errorf("REDHANDS_CREDSTORE_KEY is required to persist credentials")
	}

	for _, existing := range s.credentials {
		if existing.Username == c.Username && existing.Host == c.Host && existing.Type == c.Type && existing.Domain == c.Domain {
			c.ID = existing.ID
			break
		}
	}
	if c.ID == "" {
		c.ID = generateID()
	}
	if s.credentialStore != nil && c.Secret != "" {
		if err := s.credentialStore.Add(&credstore.Entry{ID: c.ID, Host: c.Host, Username: c.Username, Secret: c.Secret, Type: c.Type, Domain: c.Domain, Source: c.Source, Valid: c.Valid}); err != nil {
			return err
		}
	}
	copyCredential := *c
	c = &copyCredential
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
	for i, c := range s.credentials {
		copyCredential := *c
		result[i] = &copyCredential
	}
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
	s.findings = append(s.findings, cloneFinding(f))

	if s.autoSave {
		return s.save()
	}
	return nil
}

func (s *Store) ListFindings() []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Finding, len(s.findings))
	for i, f := range s.findings {
		result[i] = cloneFinding(f)
	}
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
		results = append(results, cloneFinding(f))
	}
	return results
}

func (s *Store) Snapshot() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hosts := make(map[string]*Host, len(s.hosts))
	for k, v := range s.hosts {
		hosts[k] = cloneHost(v)
	}
	services := make(map[string][]*Service, len(s.services))
	for k, v := range s.services {
		services[k] = cloneServices(v)
	}
	creds := make([]*Credential, len(s.credentials))
	for i, c := range s.credentials {
		copyCredential := *c
		creds[i] = &copyCredential
	}
	findings := make([]*Finding, len(s.findings))
	for i, f := range s.findings {
		findings[i] = cloneFinding(f)
	}

	return &Snapshot{
		Hosts:       hosts,
		Services:    services,
		Credentials: creds,
		Findings:    findings,
	}
}

func cloneHost(h *Host) *Host {
	result := *h
	result.Tags = append([]string(nil), h.Tags...)
	if h.Meta != nil {
		result.Meta = make(map[string]string, len(h.Meta))
		for k, v := range h.Meta {
			result.Meta[k] = v
		}
	}
	return &result
}

func cloneServices(services []*Service) []*Service {
	result := make([]*Service, len(services))
	for i, s := range services {
		copyService := *s
		result[i] = &copyService
	}
	return result
}

func cloneFinding(f *Finding) *Finding {
	result := *f
	result.MITRE = append([]string(nil), f.MITRE...)
	result.Raw = append([]byte(nil), f.Raw...)
	return &result
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
