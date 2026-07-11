package app

import (
	"context"
	"log"
	"net/http"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/dashboard"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

func RunTransport(ctx context.Context, srv *mcp.Server, cfg *config.Config, authCfg auth.Config, tdb *targetdb.Store) {
	if cfg.DashboardAddr != "" {
		dash := dashboard.New(tdb)
		go func() {
			log.Printf("starting dashboard on %s", cfg.DashboardAddr)
			if err := http.ListenAndServe(cfg.DashboardAddr, dash); err != nil {
				log.Printf("dashboard error: %v", err)
			}
		}()
	}

	if cfg.TCPAddr != "" {
		tcpTransport, err := mcp.NewTCPTransport(cfg.TCPAddr, srv.HandleRaw)
		if err != nil {
			log.Fatalf("failed to start TCP transport: %v", err)
		}
		defer func() { _ = tcpTransport.Close() }()
		go func() {
			log.Printf("starting TCP transport on %s", tcpTransport.Addr())
			if err := tcpTransport.Serve(); err != nil {
				log.Printf("TCP transport error: %v", err)
			}
		}()
	}

	switch cfg.Transport {
	case "sse":
		authCheck := auth.HTTPAuthCheck(authCfg)
		log.Printf("starting SSE transport on %s", cfg.SSEAddr)
		if err := srv.ServeSSEWithHandler(ctx, cfg.SSEAddr, authCheck); err != nil {
			log.Fatalf("SSE server error: %v", err)
		}
	case "ws":
		log.Printf("starting WebSocket transport on %s", cfg.WSAddr)
		if err := srv.ServeWebSocket(ctx, cfg.WSAddr); err != nil {
			log.Fatalf("WebSocket server error: %v", err)
		}
	default:
		if err := srv.ServeStdio(ctx); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}
