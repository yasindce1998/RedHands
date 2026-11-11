package app

import (
	"context"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/cache"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/dryrun"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/execution"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/opsec"
	"github.com/yasindce1998/redhands/pkg/ratelimit"
)

func SetupMiddleware(srv *mcp.Server, cfg *config.Config, auditLogger *audit.FileLogger, authCfg auth.Config, engMgr *engagement.Manager) {
	srv.SetRequestCheck(func(ctx context.Context) error { return auth.CheckContext(authCfg, ctx) })
	srv.Use(audit.Middleware(auditLogger))
	if authCfg.Mode != "none" {
		srv.Use(auth.Middleware(authCfg))
	}
	srv.Use(ratelimit.Middleware(ratelimit.New(cfg.RateLimit, cfg.RateBurst)))
	if engMgr != nil {
		srv.Use(engMgr.ScopeMiddleware)
	}
	if cfg.DryRun {
		srv.Use(dryrun.NewInterceptor().Middleware)
	}
	srv.Use(execution.Approval(cfg.ApprovedTools))
	limiter, err := execution.NewLimiter(cfg.MaxConcurrent, cfg.MaxQueued, cfg.Timeout)
	if err != nil {
		panic(err)
	} // Configuration is validated before startup.
	srv.Use(limiter.Middleware)
	srv.SetWorkflowTimeout(cfg.WorkflowTimeout)
	srv.Use(cache.MiddlewareWithPolicy(cache.New(cfg.CacheMaxSize, cfg.CacheTTL), func(ctx context.Context, name string) (string, bool) {
		identity, _ := ctx.Value(auth.ContextKeyIdentity).(string)
		engagementID := ""
		if engMgr != nil {
			if active := engMgr.Active(); active != nil {
				engagementID = active.ID
			}
		}
		policy := mcp.PolicyFromContext(ctx)
		return identity + ":" + engagementID, policy.ReadOnly && policy.Cacheable
	}))

	if cfg.OpsecProfile != "" {
		tracker := opsec.NewTracker(cfg.IOCFile)
		opsecMw := opsec.NewMiddleware(cfg.OpsecProfile, tracker)
		srv.Use(opsecMw.Wrap)
	}
}
