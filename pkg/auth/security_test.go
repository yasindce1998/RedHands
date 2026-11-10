package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmptyKeyAndUnverifiedCertificateRejected(t *testing.T) {
	for _, cfg := range []Config{{Mode: "apikey"}, {Mode: "unknown"}} {
		if _, err := HTTPAuthCheck(cfg)(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
		if cfg.Validate() == nil {
			t.Fatal("invalid configuration passed validation")
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if _, err := HTTPAuthCheck(Config{Mode: "mtls"})(req); err == nil {
		t.Fatal("unverified certificate accepted")
	}
}

func TestDashboardProtection(t *testing.T) {
	called := false
	handler := ProtectHTTP(Config{Mode: "apikey", APIKey: "secret"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if err := CheckContext(Config{Mode: "apikey", APIKey: "secret"}, r.Context()); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if called || w.Code != http.StatusUnauthorized {
		t.Fatal("dashboard accepted unauthenticated request")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("X-API-Key", "secret")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("authenticated request rejected")
	}
}

func TestMTLSHandshakeEnforcement(t *testing.T) {
	// httptest supplies a valid temporary server certificate. Trust that certificate
	// as a test CA and explicitly permit it for both sides of this loopback test.
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := seed.TLS.Certificates[0]
	seed.Close()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	server := httptest.NewUnstartedServer(ProtectHTTP(Config{Mode: "mtls"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()
	if resp, err := client.Get(server.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("mTLS accepted no client certificate")
	}
	// The certificate above is server-auth only, so it must be rejected as a client.
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()
	if resp, err := client.Get(server.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("mTLS accepted wrong certificate usage")
	}
}

func TestContextRejectsInvalidModes(t *testing.T) {
	if CheckContext(Config{Mode: "invalid"}, InjectAuthContext(context.Background(), "operator")) == nil {
		t.Fatal("invalid mode accepted")
	}
}
