package multiop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type SyncState struct {
	Hosts       []*targetdb.Host       `json:"hosts"`
	Services    []*targetdb.Service    `json:"services"`
	Credentials []*targetdb.Credential `json:"credentials"`
	Findings    []*targetdb.Finding    `json:"findings"`
	Timestamp   time.Time              `json:"timestamp"`
	OperatorID  string                 `json:"operator_id"`
}

type Peer struct {
	URL        string `json:"url"`
	OperatorID string `json:"operator_id"`
}

type SyncManager struct {
	mu         sync.RWMutex
	store      *targetdb.Store
	peers      []Peer
	operatorID string
	client     *http.Client
}

func NewSyncManager(store *targetdb.Store, operatorID string, peers []Peer) *SyncManager {
	return &SyncManager{
		store:      store,
		peers:      peers,
		operatorID: operatorID,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (sm *SyncManager) Export() *SyncState {
	return &SyncState{
		Hosts:       sm.store.ListHosts(),
		Services:    sm.store.ListServices(""),
		Credentials: sm.store.ListCredentials(),
		Findings:    sm.store.QueryFindings("", "", ""),
		Timestamp:   time.Now(),
		OperatorID:  sm.operatorID,
	}
}

func (sm *SyncManager) Import(state *SyncState) error {
	for _, h := range state.Hosts {
		if err := sm.store.AddHost(h); err != nil {
			return fmt.Errorf("import host %s: %w", h.IP, err)
		}
	}
	for _, s := range state.Services {
		if err := sm.store.AddService(s); err != nil {
			return fmt.Errorf("import service %s:%d: %w", s.Host, s.Port, err)
		}
	}
	for _, c := range state.Credentials {
		if err := sm.store.AddCredential(c); err != nil {
			return fmt.Errorf("import credential %s: %w", c.Username, err)
		}
	}
	for _, f := range state.Findings {
		if err := sm.store.AddFinding(f); err != nil {
			return fmt.Errorf("import finding %s: %w", f.ID, err)
		}
	}
	return nil
}

func (sm *SyncManager) Push() []error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	state := sm.Export()
	body, _ := json.Marshal(state)

	var errs []error
	for _, peer := range sm.peers {
		req, _ := http.NewRequest("POST", peer.URL+"/sync/push", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Operator-ID", sm.operatorID)

		resp, err := sm.client.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("push to %s: %w", peer.URL, err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("push to %s: status %d", peer.URL, resp.StatusCode))
		}
	}
	return errs
}

func (sm *SyncManager) Pull() []error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var errs []error
	for _, peer := range sm.peers {
		req, _ := http.NewRequest("GET", peer.URL+"/sync/pull", nil)
		req.Header.Set("X-Operator-ID", sm.operatorID)

		resp, err := sm.client.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("pull from %s: %w", peer.URL, err))
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var state SyncState
		if err := json.Unmarshal(body, &state); err != nil {
			errs = append(errs, fmt.Errorf("parse from %s: %w", peer.URL, err))
			continue
		}

		if err := sm.Import(&state); err != nil {
			errs = append(errs, fmt.Errorf("import from %s: %w", peer.URL, err))
		}
	}
	return errs
}

func (sm *SyncManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sync/pull":
		state := sm.Export()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(state); err != nil {
			log.Printf("sync: failed to encode pull response: %v", err)
		}

	case "/sync/push":
		body, _ := io.ReadAll(r.Body)
		var state SyncState
		if err := json.Unmarshal(body, &state); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := sm.Import(&state); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.NotFound(w, r)
	}
}
