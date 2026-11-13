package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/tools/intelligence"
	targettools "github.com/yasindce1998/redhands/tools/targetdb"
)

func setupTestServer(t *testing.T, dryRun bool) (*mcp.Server, *targetdb.Store, string, auth.Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	cfg := config.Load()
	cfg.DryRun = dryRun
	cfg.RateLimit, cfg.RateBurst = 1000, 1000
	ac := auth.Config{Mode: "apikey", APIKey: "test-only-secret"}
	srv := mcp.NewServer("test", "1")
	SetupMiddleware(srv, &cfg, logger, ac, engagement.NewManager(filepath.Join(dir, "engagements")))
	db := targetdb.NewStore(filepath.Join(dir, "db.json"), true)
	_ = srv.RegisterTool(targettools.NewAddHostTool(db))
	_ = srv.RegisterTool(targettools.NewListHostsTool(db))
	srv.SetToolPolicy("targetdb_add_host", mcp.ToolPolicy{})
	srv.SetToolPolicy("targetdb_list_hosts", mcp.ToolPolicy{ReadOnly: true})
	SetupWorkflow(srv)
	return srv, db, path, ac
}

func TestWorkflowHonorsDryRunAndAudit(t *testing.T) {
	srv, db, _, _ := setupTestServer(t, true)
	ctx := auth.InjectAuthContext(context.Background(), "test-operator")
	request := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.1"}}]}}`)
	response := srv.HandleRawContext(ctx, request)
	if !bytes.Contains(response, []byte("DRY-RUN")) {
		t.Fatalf("dry-run not applied: %s", response)
	}
	if len(db.ListHosts()) != 0 {
		t.Fatal("dry-run mutated database")
	}
}

func TestWorkflowAuthorizationAndNoMutationCaching(t *testing.T) {
	srv, db, _, _ := setupTestServer(t, false)
	ctx := auth.InjectAuthContext(context.Background(), "test-operator")
	workflow := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.1"}}]}}`)
	if response := srv.HandleRaw(workflow); !bytes.Contains(response, []byte("authentication required")) {
		t.Fatalf("unauthenticated workflow: %s", response)
	}
	if len(db.ListHosts()) != 0 {
		t.Fatal("unauthorized mutation")
	}
	if response := srv.HandleRawContext(ctx, workflow); bytes.Contains(response, []byte(`"success":false`)) {
		t.Fatalf("authorized workflow failed: %s", response)
	}
	args := json.RawMessage(`{"ip":"192.0.2.2","hostname":"original"}`)
	if _, err := srv.ExecuteTool(ctx, "targetdb_add_host", args); err != nil {
		t.Fatal(err)
	}
	if err := db.AddHost(&targetdb.Host{IP: "192.0.2.2", Hostname: "changed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.ExecuteTool(ctx, "targetdb_add_host", args); err != nil {
		t.Fatal(err)
	}
	host, _ := db.GetHost("192.0.2.2")
	if host.Hostname != "original" {
		t.Fatal("mutation was cached")
	}
	if _, err := srv.ExecuteTool(context.Background(), "targetdb_add_host", args); err == nil {
		t.Fatal("unauthenticated repeated call accepted")
	}
	if response := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"report/generate","params":{}}`)); !bytes.Contains(response, []byte("authentication required")) {
		t.Fatalf("unprotected reports: %s", response)
	}
}

func TestWarmPureCacheStillRequiresAuthentication(t *testing.T) {
	srv, _, _, _ := setupTestServer(t, false)
	_ = srv.RegisterTool(intelligence.NewMitreLookupTool())
	srv.SetToolPolicy("mitre_lookup", mcp.ToolPolicy{ReadOnly: true, Cacheable: true})
	ctx := auth.InjectAuthContext(context.Background(), "operator")
	args := json.RawMessage(`{"technique_id":"T1046"}`)
	if _, err := srv.ExecuteTool(ctx, "mitre_lookup", args); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.ExecuteTool(context.Background(), "mitre_lookup", args); err == nil {
		t.Fatal("cache bypassed authentication")
	}
}

func TestWorkflowHonorsRateLimitAndScope(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		dir := t.TempDir()
		logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = logger.Close() })
		cfg := config.Load()
		cfg.RateBurst = 1
		mgr := engagement.NewManager(filepath.Join(dir, "engagements"))
		if scoped {
			if _, err := mgr.Create("scope", "client", []string{"198.51.100.0/24"}); err != nil {
				t.Fatal(err)
			}
		}
		srv := mcp.NewServer("test", "1")
		SetupMiddleware(srv, &cfg, logger, auth.Config{Mode: "none"}, mgr)
		db := targetdb.NewStore("", false)
		_ = srv.RegisterTool(targettools.NewAddHostTool(db))
		srv.SetToolPolicy("targetdb_add_host", mcp.ToolPolicy{})
		SetupWorkflow(srv)
		response := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.1"}},{"tool":"targetdb_add_host","params":{"ip":"192.0.2.2"}}]}}`))
		if !bytes.Contains(response, []byte(`"success":false`)) {
			t.Fatalf("workflow controls bypassed: %s", response)
		}
		if scoped {
			if len(db.ListHosts()) != 0 || !bytes.Contains(response, []byte("out of scope")) {
				t.Fatalf("scope bypassed: %s", response)
			}
		} else if len(db.ListHosts()) != 1 || !bytes.Contains(response, []byte("rate limit")) {
			t.Fatalf("rate limit bypassed: %s", response)
		}
	}
}

func TestSSEWorkflowEndToEnd(t *testing.T) {
	srv, db, _, ac := setupTestServer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpSrv := httptest.NewServer(srv.SSEHandler(ctx, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)}))
	defer httpSrv.Close()
	unauthorized, err := http.Get(httpSrv.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatal("SSE authentication not enforced")
	}
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/sse", nil)
	req.Header.Set("X-API-Key", ac.APIKey)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Body.Close() }()
	reader := bufio.NewReader(stream.Body)
	_, _ = reader.ReadString('\n')
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	endpoint := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
	_, _ = reader.ReadString('\n')
	post, _ := http.NewRequest(http.MethodPost, httpSrv.URL+endpoint, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.8"}}]}}`))
	post.Header.Set("X-API-Key", ac.APIKey)
	response, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST status: %d", response.StatusCode)
	}
	_, _ = reader.ReadString('\n')
	result, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, `"success":true`) {
		t.Fatalf("workflow result: %s", result)
	}
	if _, ok := db.GetHost("192.0.2.8"); !ok {
		t.Fatal("workflow did not execute")
	}
}

func TestValidateConfigRejectsUnsafeListeners(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*config.Config, *auth.Config)
	}{
		{"public unauthenticated", func(c *config.Config, a *auth.Config) { c.Transport = "sse"; c.SSEAddr = ":8080" }},
		{"public without TLS", func(c *config.Config, a *auth.Config) {
			c.Transport = "ws"
			c.WSAddr = ":8081"
			a.Mode = "apikey"
			a.APIKey = "secret"
		}},
		{"empty API key", func(c *config.Config, a *auth.Config) { c.Transport = "sse"; a.Mode = "apikey" }},
		{"stdio auth unsupported", func(c *config.Config, a *auth.Config) { a.Mode = "apikey"; a.APIKey = "secret" }},
		{"TCP API key unsupported", func(c *config.Config, a *auth.Config) {
			c.Transport = "sse"
			c.TCPAddr = "127.0.0.1:9000"
			a.Mode = "apikey"
			a.APIKey = "secret"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ac := config.Load(), auth.Config{Mode: "none"}
			tc.configure(&cfg, &ac)
			if err := ValidateConfig(&cfg, ac); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	if err := ValidateConfig(ptrConfig(config.Load()), auth.Config{Mode: "none"}); err != nil {
		t.Fatal(err)
	}
}

func ptrConfig(c config.Config) *config.Config { return &c }

func TestDryRunWorkflowWritesAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer("test", "1")
	cfg := config.Load()
	cfg.DryRun = true
	SetupMiddleware(srv, &cfg, logger, auth.Config{Mode: "none"}, nil)
	db := targetdb.NewStore("", false)
	_ = srv.RegisterTool(targettools.NewAddHostTool(db))
	SetupWorkflow(srv)
	srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.1"}}]}}`))
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("targetdb_add_host")) {
		t.Fatalf("missing audit event: %s", data)
	}
	if len(db.ListHosts()) != 0 {
		t.Fatal("dry-run mutated database")
	}
}
