package main

import (
	"context"
	"log"
	"os"

	"github.com/yasindce1998/redhands/internal/app"
	"github.com/yasindce1998/redhands/internal/binaries"
	"github.com/yasindce1998/redhands/internal/registry"
	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func main() {
	log.SetOutput(os.Stderr)

	cfg := config.Load()
	authCfg := auth.LoadConfig()

	execr := executor.New(executor.Config{
		Timeout:         int64(cfg.Timeout.Seconds()),
		AllowedBinaries: binaries.Discover(),
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})

	auditLogger, err := audit.NewFileLogger(cfg.AuditFile)
	if err != nil {
		log.Fatalf("failed to initialize audit logger: %v", err)
	}
	defer func() { _ = auditLogger.Close() }()

	stores := app.InitStores(&cfg)

	srv := mcp.NewServer("redhands", "0.1.0")

	app.SetupMiddleware(srv, &cfg, auditLogger, authCfg)

	registry.RegisterAll(srv, &registry.Deps{
		Exec:      execr,
		Cfg:       &cfg,
		TargetDB:  stores.TargetDB,
		Graph:     stores.Graph,
		EngMgr:    stores.EngMgr,
		Loot:      stores.Loot,
		CredStore: stores.CredStore,
		Evidence:  stores.Evidence,
	})

	stopPlugins := app.SetupPlugins(srv, &cfg, execr)
	defer stopPlugins()

	app.SetupWorkflow(srv)

	app.RunTransport(context.Background(), srv, &cfg, authCfg, stores.TargetDB)
}
