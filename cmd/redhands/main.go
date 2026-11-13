package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yasindce1998/redhands/internal/app"
	"github.com/yasindce1998/redhands/internal/binaries"
	"github.com/yasindce1998/redhands/internal/registry"
	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/version"
)

func main() {
	log.SetOutput(os.Stderr)
	if err := run(); err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Load()
	authCfg := auth.LoadConfig()
	if err := app.ValidateConfig(&cfg, authCfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	execr := executor.New(executor.Config{
		Timeout:         int64(cfg.Timeout.Seconds()),
		AllowedBinaries: binaries.Discover(),
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})
	procMgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: binaries.Discover(),
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})
	defer procMgr.StopAll()

	auditLogger, err := audit.NewFileLogger(cfg.AuditFile)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}
	defer func() { _ = auditLogger.Close() }()

	stores, err := app.InitStores(&cfg)
	if err != nil {
		return err
	}

	srv := mcp.NewServer("redhands", version.Version)

	app.SetupMiddleware(srv, &cfg, auditLogger, authCfg, stores.EngMgr)

	stopPlugins := app.SetupPlugins(srv, &cfg, execr)
	defer stopPlugins()

	app.SetupWorkflow(srv)
	campaignEngine := app.SetupCampaign(srv, &cfg, stores.TargetDB, stores.EngMgr)

	registry.RegisterAll(srv, &registry.Deps{
		Exec:        execr,
		Cfg:         &cfg,
		TargetDB:    stores.TargetDB,
		Graph:       stores.Graph,
		EngMgr:      stores.EngMgr,
		Loot:        stores.Loot,
		CredStore:   stores.CredStore,
		Evidence:    stores.Evidence,
		ProcMgr:     procMgr,
		CampaignEng: campaignEngine,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := app.RunTransport(ctx, srv, &cfg, authCfg, stores.TargetDB); err != nil {
		if !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return nil
}
