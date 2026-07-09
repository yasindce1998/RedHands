package targetdb

import (
	"encoding/json"
	"os"
)

func (s *Store) save() error {
	if s.filePath == "" {
		return nil
	}
	snap := &Snapshot{
		Hosts:       s.hosts,
		Services:    s.services,
		Credentials: s.credentials,
		Findings:    s.findings,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0600)
}

func (s *Store) Load() error {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.save()
}
