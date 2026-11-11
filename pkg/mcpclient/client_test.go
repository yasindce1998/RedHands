package mcpclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestTrustedTLSAndAPIKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := mcp.NewServer("test", "1")
	ac := auth.Config{Mode: "apikey", APIKey: "secret"}
	srv.SetRequestCheck(func(ctx context.Context) error { return auth.CheckContext(ac, ctx) })
	server := httptest.NewTLSServer(srv.SSEHandler(ctx, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := Dial(ctx, Config{URL: server.URL, APIKey: "secret", CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Call(ctx, mcp.MethodPing, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if client, err := Dial(ctx, Config{URL: server.URL, APIKey: "secret"}); err == nil {
		client.Close()
		t.Fatal("untrusted certificate accepted")
	}
}

func TestForeignEndpointAndRedirectRejected(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirect {
				http.Redirect(w, r, "http://example.invalid/sse", http.StatusTemporaryRedirect)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "event: endpoint\ndata: http://example.invalid/message\n\n")
			w.(http.Flusher).Flush()
		}))
		client, err := Dial(ctx, Config{URL: server.URL, APIKey: "do-not-leak"})
		if err == nil {
			client.Close()
			t.Fatal("foreign endpoint or redirect accepted")
		}
		server.Close()
		cancel()
	}
}

func TestDeadlineAndInvalidConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if c, err := Dial(ctx, Config{URL: server.URL}); err == nil {
		c.Close()
		t.Fatal("missing endpoint ignored deadline")
	}
	for _, url := range []string{"file:///etc/passwd", "http://user:secret@localhost", "http://localhost?api_key=secret"} {
		if c, err := Dial(context.Background(), Config{URL: url}); err == nil {
			c.Close()
			t.Fatalf("accepted %s", url)
		}
	}
	if _, err := NewHTTPClient(Config{CertFile: "only-cert"}); err == nil {
		t.Fatal("unpaired certificate accepted")
	}
}

func TestSSEMultilineAndBoundedData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{body: ioNopCloser("event: message\ndata: one\ndata: two\n\n"), events: make(chan event, 2)}
	c.readEvents(ctx)
	e := <-c.events
	if e.data != "one\ntwo" {
		t.Fatalf("multiline data: %q", e.data)
	}
}

func TestClientCertificateAuthentication(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(name string, usage x509.ExtKeyUsage) (string, string) {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
			t.Fatal(err)
		}
		return certFile, keyFile
	}
	serverCert, serverKey := issue("server", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issue("operator", x509.ExtKeyUsageClientAuth)
	ac := auth.Config{Mode: "mtls", TLSCert: serverCert, TLSKey: serverKey, TLSCA: caFile}
	tlsConfig, err := auth.TLSConfig(ac)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := mcp.NewServer("test", "1")
	srv.SetRequestCheck(func(ctx context.Context) error { return auth.CheckContext(ac, ctx) })
	server := httptest.NewUnstartedServer(srv.SSEHandler(ctx, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)}))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()
	// NewHTTPClient's TLS configuration is tested directly with a matching server
	// name, since httptest binds an IP while this certificate names localhost.
	hc, err := NewHTTPClient(Config{CAFile: caFile, CertFile: clientCert, KeyFile: clientKey})
	if err != nil {
		t.Fatal(err)
	}
	defer hc.CloseIdleConnections()
	hc.Transport.(*http.Transport).TLSClientConfig.ServerName = "localhost"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := hc.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("mTLS status: %d", response.StatusCode)
	}
}

func TestLostResponseIsNotRetried(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv := mcp.NewServer("test", "1")
	var calls int
	handler := srv.SSEHandler(ctx, mcp.HTTPOptions{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if strings.Contains(string(data), `"tools/call"`) {
				calls++
				http.Error(w, "response lost", http.StatusInternalServerError)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(data)))
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	c, err := Dial(ctx, Config{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Call(ctx, mcp.MethodToolsCall, mcp.ToolsCallParams{Name: "test"}); err == nil {
		t.Fatal("failed response accepted")
	}
	if calls != 1 {
		t.Fatalf("request replayed %d times", calls)
	}
}

func TestConcurrentCallWaitHonorsDeadline(t *testing.T) {
	c := &Client{gate: make(chan struct{}, 1)}
	c.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, "ping", struct{}{}); err == nil {
		t.Fatal("waiting call ignored deadline")
	}
}

type stringBody struct{ *strings.Reader }

func (stringBody) Close() error       { return nil }
func ioNopCloser(s string) stringBody { return stringBody{strings.NewReader(s)} }
