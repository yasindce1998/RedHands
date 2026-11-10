package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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

func (cfg Config) Validate() error {
	switch cfg.Mode {
	case "none", "mtls":
	case "apikey":
		if strings.TrimSpace(cfg.APIKey) == "" || cfg.APIKey == "changeme" {
			return fmt.Errorf("REDHANDS_API_KEY must be a non-empty, non-default secret")
		}
	default:
		return fmt.Errorf("unknown authentication mode %q", cfg.Mode)
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return fmt.Errorf("TLS certificate and key must be configured together")
	}
	if cfg.Mode == "mtls" && (cfg.TLSCert == "" || cfg.TLSCA == "") {
		return fmt.Errorf("mTLS requires REDHANDS_TLS_CERT, REDHANDS_TLS_KEY and REDHANDS_TLS_CA")
	}
	return nil
}

func CheckContext(cfg Config, ctx context.Context) error {
	if cfg.Mode == "none" {
		return nil
	}
	if cfg.Mode != "apikey" && cfg.Mode != "mtls" {
		return fmt.Errorf("invalid authentication mode")
	}
	if cfg.Mode == "apikey" && strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("API key is not configured")
	}
	if authed, _ := ctx.Value(ContextKeyAuthenticated).(bool); !authed {
		return fmt.Errorf("authentication required")
	}
	return nil
}

// TLSConfig builds server TLS settings for API-key or mutual-TLS deployments.
func TLSConfig(cfg Config) (*tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Mode == "mtls" {
		return MTLSConfig(cfg)
	}
	if cfg.TLSCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading server cert: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Middleware returns an MCP middleware that checks auth context.
// For HTTP transports, auth is injected into context by the HTTP handler.
// stdio relies on local OS access controls and must use mode "none".
func Middleware(cfg Config) mcp.Middleware {
	return func(next mcp.ToolHandler) mcp.ToolHandler {
		return func(ctx context.Context, toolName string, args json.RawMessage) (*mcp.ToolResult, error) {
			if err := CheckContext(cfg, ctx); err != nil {
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
			if strings.TrimSpace(cfg.APIKey) == "" || key == "" || !secureCompare(key, cfg.APIKey) {
				return nil, fmt.Errorf("invalid or missing API key")
			}
			ctx := context.WithValue(r.Context(), ContextKeyAuthenticated, true)
			ctx = context.WithValue(ctx, ContextKeyIdentity, "apikey")
			return ctx, nil
		}

		if cfg.Mode != "mtls" {
			return nil, fmt.Errorf("invalid authentication mode")
		}
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
			cn := certificateIdentity(r.TLS.PeerCertificates[0])
			ctx := context.WithValue(r.Context(), ContextKeyAuthenticated, true)
			ctx = context.WithValue(ctx, ContextKeyIdentity, cn)
			return ctx, nil
		}

		return nil, fmt.Errorf("client certificate required")
	}
}

// ProtectHTTP applies the same authentication policy to auxiliary HTTP services.
func ProtectHTTP(cfg Config, next http.Handler) http.Handler {
	check := HTTPAuthCheck(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := check(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
// Used by transports only after successfully validating credentials.
func InjectAuthContext(ctx context.Context, identity string) context.Context {
	ctx = context.WithValue(ctx, ContextKeyAuthenticated, true)
	ctx = context.WithValue(ctx, ContextKeyIdentity, identity)
	return ctx
}

func certificateIdentity(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return cert.Subject.String() + ":" + hex.EncodeToString(fingerprint[:])
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
