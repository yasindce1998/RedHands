package targetdb

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/redhands/pkg/storage"
)

func (s *Store) save() error {
	if s.loadErr != nil {
		return fmt.Errorf("database load failed; refusing overwrite: %w", s.loadErr)
	}
	if s.filePath == "" {
		return nil
	}
	credentials := make([]*Credential, 0, len(s.credentials))
	for _, c := range s.credentials {
		if c.Secret != "" && s.credentialStore == nil {
			return fmt.Errorf("refusing to persist credential secrets without an encrypted credential store")
		}
		metadata := *c
		metadata.Secret = ""
		credentials = append(credentials, &metadata)
	}
	snap := &Snapshot{
		Hosts:       s.hosts,
		Services:    s.services,
		Credentials: credentials,
		Findings:    s.findings,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return storage.WriteFile(s.filePath, data)
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.filePath == "" {
		return nil
	}
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	for _, c := range snap.Credentials {
		if c == nil {
			return fmt.Errorf("invalid null credential record")
		}
		if c.Secret != "" {
			return fmt.Errorf("legacy plaintext credentials found in %s; migrate them to the encrypted store before loading", s.filePath)
		}
	}
	for _, h := range snap.Hosts {
		if h == nil {
			return fmt.Errorf("invalid null host record")
		}
	}
	for _, services := range snap.Services {
		for _, service := range services {
			if service == nil {
				return fmt.Errorf("invalid null service record")
			}
		}
	}
	for _, f := range snap.Findings {
		if f == nil {
			return fmt.Errorf("invalid null finding record")
		}
	}
	if snap.Hosts != nil {
		s.hosts = snap.Hosts
	}
	if snap.Services != nil {
		s.services = snap.Services
	}
	s.credentials = snap.Credentials
	s.findings = snap.Findings
	return nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}
