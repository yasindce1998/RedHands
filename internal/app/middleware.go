package app

import (
	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/cache"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/dryrun"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/opsec"
	"github.com/yasindce1998/redhands/pkg/ratelimit"
)

func SetupMiddleware(srv *mcp.Server, cfg *config.Config, auditLogger *audit.FileLogger, authCfg auth.Config) {
	if cfg.DryRun {
		dryrunInterceptor := dryrun.NewInterceptor()
		srv.Use(dryrunInterceptor.Middleware)
	}

	srv.Use(audit.Middleware(auditLogger))
	srv.Use(ratelimit.Middleware(ratelimit.New(cfg.RateLimit, cfg.RateBurst)))
	srv.Use(cache.Middleware(cache.New(cfg.CacheMaxSize, cfg.CacheTTL)))

	if authCfg.Mode != "none" {
		srv.Use(auth.Middleware(authCfg))
	}

	if cfg.OpsecProfile != "" {
		tracker := opsec.NewTracker(cfg.IOCFile)
		opsecMw := opsec.NewMiddleware(cfg.OpsecProfile, tracker)
		srv.Use(opsecMw.Wrap)
	}
}
