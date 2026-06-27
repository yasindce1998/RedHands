package auth

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

type contextKey string

const (
	ContextKeyAuthenticated contextKey = "auth.authenticated"
	ContextKeyIdentity      contextKey = "auth.identity"
)

type Config struct {
	Mode    string // "none", "apikey", "mtls"
	APIKey  string
	TLSCert string
	TLSKey  string
	TLSCA   string
}

func LoadConfig() Config {
	return Config{
		Mode:    envOrDefault("REDHANDS_AUTH", "none"),
		APIKey:  os.Getenv("REDHANDS_API_KEY"),
		TLSCert: os.Getenv("REDHANDS_TLS_CERT"),
		TLSKey:  os.Getenv("REDHANDS_TLS_KEY"),
		TLSCA:   os.Getenv("REDHANDS_TLS_CA"),
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Middleware returns an MCP middleware that checks auth context.
// For HTTP transports, auth is injected into context by the HTTP handler.
// For stdio, the API key can be sent in the initialize params.
func Middleware(cfg Config) mcp.Middleware {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, toolName string, args json.RawMessage) (*mcp.ToolResult, error) {
			if cfg.Mode == "none" {
				return next(ctx, toolName, args)
			}

			authed, _ := ctx.Value(ContextKeyAuthenticated).(bool)
			if !authed {
				return &mcp.ToolResult{
					Content: []mcp.ContentBlock{{Type: "text", Text: "Error: authentication required"}},
					IsError: true,
				}, nil
			}

			return next(ctx, toolName, args)
		}
	}
}

// HTTPAuthCheck returns a function suitable for ServeSSEWithHandler that
// validates the API key from the X-API-Key header.
func HTTPAuthCheck(cfg Config) func(r *http.Request) (context.Context, error) {
	return func(r *http.Request) (context.Context, error) {
		if cfg.Mode == "none" {
			ctx := context.WithValue(r.Context(), ContextKeyAuthenticated, true)
			return ctx, nil
		}

		if cfg.Mode == "apikey" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.URL.Query().Get("api_key")
			}
			if !secureCompare(key, cfg.APIKey) {
				return nil, fmt.Errorf("invalid or missing API key")
			}
			ctx := context.WithValue(r.Context(), ContextKeyAuthenticated, true)
			ctx = context.WithValue(ctx, ContextKeyIdentity, "apikey")
			return ctx, nil
		}

		// mTLS: client cert is already validated by TLS config; just check it exists
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn := r.TLS.PeerCertificates[0].Subject.CommonName
			ctx := context.WithValue(r.Context(), ContextKeyAuthenticated, true)
			ctx = context.WithValue(ctx, ContextKeyIdentity, cn)
			return ctx, nil
		}

		return nil, fmt.Errorf("client certificate required")
	}
}

// MTLSConfig builds a tls.Config for mTLS servers.
func MTLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading server cert: %w", err)
	}

	caCert, err := os.ReadFile(cfg.TLSCA)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// InjectAuthContext creates a context with auth set to true.
// Used by stdio transport when API key is provided in initialize params.
func InjectAuthContext(ctx context.Context, identity string) context.Context {
	ctx = context.WithValue(ctx, ContextKeyAuthenticated, true)
	ctx = context.WithValue(ctx, ContextKeyIdentity, identity)
	return ctx
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
