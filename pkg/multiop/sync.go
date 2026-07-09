package multiop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func (sm *SyncManager) Import(state *SyncState) {
	for _, h := range state.Hosts {
		sm.store.AddHost(h)
	}
	for _, s := range state.Services {
		sm.store.AddService(s)
	}
	for _, c := range state.Credentials {
		sm.store.AddCredential(c)
	}
	for _, f := range state.Findings {
		sm.store.AddFinding(f)
	}
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
		resp.Body.Close()
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

		sm.Import(&state)
	}
	return errs
}

func (sm *SyncManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sync/pull":
		state := sm.Export()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)

	case "/sync/push":
		body, _ := io.ReadAll(r.Body)
		var state SyncState
		if err := json.Unmarshal(body, &state); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sm.Import(&state)
		w.WriteHeader(http.StatusOK)

	default:
		http.NotFound(w, r)
	}
}
