package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- Middleware tests ---

func TestMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		cfg           Config
		ctx           context.Context
		wantCalled    bool
		wantIsError   bool
		wantErrorText string
	}{
		{
			name:       "mode none always passes through",
			cfg:        Config{Mode: "none"},
			ctx:        context.Background(),
			wantCalled: true,
		},
		{
			name:       "mode apikey passes when authenticated",
			cfg:        Config{Mode: "apikey", APIKey: "secret"},
			ctx:        context.WithValue(context.Background(), ContextKeyAuthenticated, true),
			wantCalled: true,
		},
		{
			name:          "mode apikey blocks when unauthenticated",
			cfg:           Config{Mode: "apikey", APIKey: "secret"},
			ctx:           context.Background(),
			wantCalled:    false,
			wantIsError:   true,
			wantErrorText: "Error: authentication required",
		},
		{
			name:          "mode mtls blocks when unauthenticated",
			cfg:           Config{Mode: "mtls"},
			ctx:           context.Background(),
			wantCalled:    false,
			wantIsError:   true,
			wantErrorText: "Error: authentication required",
		},
		{
			name:       "mode mtls passes when authenticated",
			cfg:        Config{Mode: "mtls"},
			ctx:        context.WithValue(context.Background(), ContextKeyAuthenticated, true),
			wantCalled: true,
		},
		{
			name:          "mode apikey blocks when auth context value is false",
			cfg:           Config{Mode: "apikey", APIKey: "secret"},
			ctx:           context.WithValue(context.Background(), ContextKeyAuthenticated, false),
			wantCalled:    false,
			wantIsError:   true,
			wantErrorText: "Error: authentication required",
		},
		{
			name:          "mode apikey blocks when auth context value is wrong type",
			cfg:           Config{Mode: "apikey", APIKey: "secret"},
			ctx:           context.WithValue(context.Background(), ContextKeyAuthenticated, "yes"),
			wantCalled:    false,
			wantIsError:   true,
			wantErrorText: "Error: authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := Middleware(tt.cfg)

			called := false
			handler := mw(func(ctx context.Context, toolName string, args json.RawMessage) (*mcp.ToolResult, error) {
				called = true
				return &mcp.ToolResult{
					Content: []mcp.ContentBlock{{Type: "text", Text: "ok"}},
				}, nil
			})

			result, err := handler(tt.ctx, "test_tool", json.RawMessage(`{}`))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if called != tt.wantCalled {
				t.Errorf("handler called = %v, want %v", called, tt.wantCalled)
			}
			if result.IsError != tt.wantIsError {
				t.Errorf("result.IsError = %v, want %v", result.IsError, tt.wantIsError)
			}
			if tt.wantErrorText != "" && result.Content[0].Text != tt.wantErrorText {
				t.Errorf("error text = %q, want %q", result.Content[0].Text, tt.wantErrorText)
			}
		})
	}
}

// --- HTTPAuthCheck tests ---

func TestHTTPAuthCheck(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		setupReq     func() *http.Request
		wantErr      bool
		wantErrMsg   string
		wantAuthed   bool
		wantIdentity string
	}{
		{
			name: "mode none always authenticates",
			cfg:  Config{Mode: "none"},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantAuthed: true,
		},
		{
			name: "valid API key in header",
			cfg:  Config{Mode: "apikey", APIKey: "correct-key"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "correct-key")
				return req
			},
			wantAuthed:   true,
			wantIdentity: "apikey",
		},
		{
			name: "valid API key in query param",
			cfg:  Config{Mode: "apikey", APIKey: "query-secret"},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/?api_key=query-secret", nil)
			},
			wantAuthed:   true,
			wantIdentity: "apikey",
		},
		{
			name: "header takes precedence over query param",
			cfg:  Config{Mode: "apikey", APIKey: "header-key"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/?api_key=wrong-key", nil)
				req.Header.Set("X-API-Key", "header-key")
				return req
			},
			wantAuthed:   true,
			wantIdentity: "apikey",
		},
		{
			name: "invalid API key returns error",
			cfg:  Config{Mode: "apikey", APIKey: "correct-key"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "wrong-key")
				return req
			},
			wantErr:    true,
			wantErrMsg: "invalid or missing API key",
		},
		{
			name: "missing API key returns error",
			cfg:  Config{Mode: "apikey", APIKey: "some-key"},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantErr:    true,
			wantErrMsg: "invalid or missing API key",
		},
		{
			name: "empty API key in header returns error",
			cfg:  Config{Mode: "apikey", APIKey: "real-key"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-API-Key", "")
				return req
			},
			wantErr:    true,
			wantErrMsg: "invalid or missing API key",
		},
		{
			name: "mtls mode with client cert authenticates",
			cfg:  Config{Mode: "mtls"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						{Subject: pkix.Name{CommonName: "client.example.com"}},
					},
				}
				return req
			},
			wantAuthed:   true,
			wantIdentity: "client.example.com",
		},
		{
			name: "mtls mode without TLS info returns error",
			cfg:  Config{Mode: "mtls"},
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantErr:    true,
			wantErrMsg: "client certificate required",
		},
		{
			name: "mtls mode with empty peer certs returns error",
			cfg:  Config{Mode: "mtls"},
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{},
				}
				return req
			},
			wantErr:    true,
			wantErrMsg: "client certificate required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := HTTPAuthCheck(tt.cfg)
			req := tt.setupReq()

			ctx, err := check(req)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantErrMsg != "" && err.Error() != tt.wantErrMsg {
					t.Errorf("error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			authed, ok := ctx.Value(ContextKeyAuthenticated).(bool)
			if tt.wantAuthed && (!ok || !authed) {
				t.Error("expected authenticated=true in context")
			}

			if tt.wantIdentity != "" {
				identity, ok := ctx.Value(ContextKeyIdentity).(string)
				if !ok || identity != tt.wantIdentity {
					t.Errorf("identity = %q, want %q", identity, tt.wantIdentity)
				}
			}
		})
	}
}

// --- MTLSConfig tests ---

func TestMTLSConfig(t *testing.T) {
	// Helper to generate self-signed CA, server cert, and key in temp files.
	generateCerts := func(t *testing.T, dir string) (certPath, keyPath, caPath string) {
		t.Helper()

		// Generate CA key and cert
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating CA key: %v", err)
		}

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(1 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("creating CA cert: %v", err)
		}

		caPath = filepath.Join(dir, "ca.pem")
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
		if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
			t.Fatalf("writing CA cert: %v", err)
		}

		// Generate server key and cert signed by CA
		serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating server key: %v", err)
		}

		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		caCert, err := x509.ParseCertificate(caCertDER)
		if err != nil {
			t.Fatalf("parsing CA cert: %v", err)
		}

		serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("creating server cert: %v", err)
		}

		certPath = filepath.Join(dir, "server.pem")
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			t.Fatalf("writing server cert: %v", err)
		}

		keyPath = filepath.Join(dir, "server-key.pem")
		serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
		if err != nil {
			t.Fatalf("marshaling server key: %v", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			t.Fatalf("writing server key: %v", err)
		}

		return certPath, keyPath, caPath
	}

	t.Run("valid certs return proper tls.Config", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath, caPath := generateCerts(t, dir)

		cfg := Config{
			Mode:    "mtls",
			TLSCert: certPath,
			TLSKey:  keyPath,
			TLSCA:   caPath,
		}

		tlsCfg, err := MTLSConfig(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
		}
		if tlsCfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %v, want TLS 1.2 (%v)", tlsCfg.MinVersion, tls.VersionTLS12)
		}
		if len(tlsCfg.Certificates) != 1 {
			t.Errorf("Certificates count = %d, want 1", len(tlsCfg.Certificates))
		}
		if tlsCfg.ClientCAs == nil {
			t.Error("ClientCAs should not be nil")
		}
	})

	t.Run("missing cert file returns error", func(t *testing.T) {
		dir := t.TempDir()
		_, _, caPath := generateCerts(t, dir)

		cfg := Config{
			Mode:    "mtls",
			TLSCert: filepath.Join(dir, "nonexistent.pem"),
			TLSKey:  filepath.Join(dir, "nonexistent-key.pem"),
			TLSCA:   caPath,
		}

		_, err := MTLSConfig(cfg)
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("missing CA file returns error", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath, _ := generateCerts(t, dir)

		cfg := Config{
			Mode:    "mtls",
			TLSCert: certPath,
			TLSKey:  keyPath,
			TLSCA:   filepath.Join(dir, "nonexistent-ca.pem"),
		}

		_, err := MTLSConfig(cfg)
		if err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("invalid CA PEM returns error", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath, _ := generateCerts(t, dir)

		badCAPath := filepath.Join(dir, "bad-ca.pem")
		if err := os.WriteFile(badCAPath, []byte("not a valid PEM"), 0600); err != nil {
			t.Fatalf("writing bad CA: %v", err)
		}

		cfg := Config{
			Mode:    "mtls",
			TLSCert: certPath,
			TLSKey:  keyPath,
			TLSCA:   badCAPath,
		}

		_, err := MTLSConfig(cfg)
		if err == nil {
			t.Fatal("expected error for invalid CA PEM")
		}
	})
}

// --- InjectAuthContext tests ---

func TestInjectAuthContext(t *testing.T) {
	tests := []struct {
		name         string
		identity     string
		wantAuthed   bool
		wantIdentity string
	}{
		{
			name:         "sets auth and identity for user",
			identity:     "test-user",
			wantAuthed:   true,
			wantIdentity: "test-user",
		},
		{
			name:         "works with empty identity",
			identity:     "",
			wantAuthed:   true,
			wantIdentity: "",
		},
		{
			name:         "works with complex identity string",
			identity:     "CN=client.example.com,O=Org,C=US",
			wantAuthed:   true,
			wantIdentity: "CN=client.example.com,O=Org,C=US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := InjectAuthContext(context.Background(), tt.identity)

			authed, ok := ctx.Value(ContextKeyAuthenticated).(bool)
			if !ok || authed != tt.wantAuthed {
				t.Errorf("authenticated = %v, want %v", authed, tt.wantAuthed)
			}

			identity, ok := ctx.Value(ContextKeyIdentity).(string)
			if !ok || identity != tt.wantIdentity {
				t.Errorf("identity = %q, want %q", identity, tt.wantIdentity)
			}
		})
	}

	t.Run("preserves parent context values", func(t *testing.T) {
		type customKey string
		parentCtx := context.WithValue(context.Background(), customKey("existing"), "value")
		ctx := InjectAuthContext(parentCtx, "user1")

		val, ok := ctx.Value(customKey("existing")).(string)
		if !ok || val != "value" {
			t.Error("parent context values should be preserved")
		}

		authed, _ := ctx.Value(ContextKeyAuthenticated).(bool)
		if !authed {
			t.Error("expected authenticated=true")
		}
	})
}
