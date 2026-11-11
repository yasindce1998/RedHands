package app

import (
	"fmt"
	"log"

	"github.com/yasindce1998/redhands/pkg/attackgraph"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/credstore"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/loot"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

type Stores struct {
	TargetDB  *targetdb.Store
	Graph     *attackgraph.Graph
	EngMgr    *engagement.Manager
	Loot      *loot.Store
	CredStore *credstore.Store
	Evidence  *evidence.Store
}

func InitStores(cfg *config.Config) (*Stores, error) {
	s := &Stores{}

	s.TargetDB = targetdb.NewStore(cfg.TargetDBFile, cfg.TargetDBAutoSave)
	if err := s.TargetDB.LoadError(); err != nil {
		return nil, fmt.Errorf("target database: %w", err)
	}
	s.Graph = attackgraph.New()
	s.EngMgr = engagement.NewManager(cfg.EngagementDir)

	var err error
	s.Loot, err = loot.NewStore(cfg.LootDir)
	if err != nil {
		return nil, fmt.Errorf("loot store: %w", err)
	}

	if cfg.CredStoreKey != "" {
		s.CredStore, err = credstore.NewStore(cfg.CredStoreFile, cfg.CredStoreKey)
		if err != nil {
			return nil, fmt.Errorf("credstore initialization failed: %w", err)
		}
		s.TargetDB.SetCredentialStore(s.CredStore)
	}

	s.Evidence, err = evidence.NewStore(cfg.EvidenceDir)
	if err != nil {
		log.Printf("warning: evidence store initialization failed: %v", err)
	}

	return s, nil
}
