package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/dashboard"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

func ValidateConfig(cfg *config.Config, ac auth.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := ac.Validate(); err != nil {
		return err
	}
	if cfg.Transport == "stdio" && ac.Mode != "none" {
		return fmt.Errorf("stdio uses local OS access controls; use REDHANDS_AUTH=none or an authenticated network transport")
	}
	if cfg.TCPAddr != "" && ac.Mode == "apikey" {
		return fmt.Errorf("TCP does not support API-key headers; use mTLS or SSE/WebSocket")
	}
	addresses := []string{cfg.DashboardAddr, cfg.TCPAddr}
	if cfg.Transport == "sse" {
		addresses = append(addresses, cfg.SSEAddr)
	}
	if cfg.Transport == "ws" {
		addresses = append(addresses, cfg.WSAddr)
	}
	if cfg.Transport == "http" {
		addresses = append(addresses, cfg.HTTPAddr)
	}
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid listen address %q: %w", addr, err)
		}
		ip := net.ParseIP(host)
		loopback := ip != nil && ip.IsLoopback()
		if !loopback && (ac.Mode == "none" || ac.TLSCert == "") {
			return fmt.Errorf("non-loopback listener %q requires authentication and TLS", addr)
		}
	}
	_, err := auth.TLSConfig(ac)
	return err
}

func RunTransport(ctx context.Context, srv *mcp.Server, cfg *config.Config, ac auth.Config, tdb *targetdb.Store) error {
	// The streamable HTTP transport only listens when selected; make sure
	// it never falls back to an all-interfaces default.
	if cfg.Transport == "http" {
		if cfg.HTTPAddr == "" {
			cfg.HTTPAddr = "127.0.0.1:8082"
		}
		if cfg.HTTPPath == "" {
			cfg.HTTPPath = mcp.DefaultHTTPPath
		}
	}
	if err := ValidateConfig(cfg, ac); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tlsCfg, err := auth.TLSConfig(ac)
	if err != nil {
		return err
	}
	opts := mcp.HTTPOptions{TLSConfig: tlsCfg, AuthCheck: auth.HTTPAuthCheck(ac), Identity: func(ctx context.Context) string {
		id, _ := ctx.Value(auth.ContextKeyIdentity).(string)
		return id
	}}
	if cfg.DashboardAddr != "" {
		ln, err := net.Listen("tcp", cfg.DashboardAddr)
		if err != nil {
			return err
		}
		if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg)
		}
		dash := &http.Server{Handler: auth.ProtectHTTP(ac, dashboard.New(tdb)), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
		defer func() { _ = dash.Close() }()
		go func() {
			if err := dash.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("dashboard: %v", err)
			}
		}()
	}
	if cfg.TCPAddr != "" {
		tcpOpts := mcp.TCPOptions{TLSConfig: tlsCfg}
		if ac.Mode == "mtls" {
			tcpOpts.Authenticate = func(ctx context.Context, conn net.Conn) (context.Context, error) {
				tc, ok := conn.(*tls.Conn)
				if !ok {
					return nil, fmt.Errorf("TLS required")
				}
				if err := tc.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				state := tc.ConnectionState()
				if len(state.VerifiedChains) == 0 {
					return nil, fmt.Errorf("verified client certificate required")
				}
				return auth.InjectAuthContext(ctx, state.PeerCertificates[0].Subject.String()), nil
			}
		}
		tcp, err := mcp.NewTCPTransportWithOptions(ctx, cfg.TCPAddr, srv.HandleRawContext, tcpOpts)
		if err != nil {
			return err
		}
		defer func() { _ = tcp.Close() }()
		go func() {
			if err := tcp.Serve(); err != nil {
				log.Printf("TCP: %v", err)
			}
		}()
	}
	switch cfg.Transport {
	case "sse":
		return srv.ServeSSEWithOptions(ctx, cfg.SSEAddr, opts)
	case "ws":
		return srv.ServeWebSocketWithOptions(ctx, cfg.WSAddr, opts)
	case "http":
		return srv.ServeStreamableHTTPWithPath(ctx, cfg.HTTPAddr, cfg.HTTPPath, opts)
	default:
		return srv.ServeStdio(ctx)
	}
}
