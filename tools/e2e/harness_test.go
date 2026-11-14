//go:build livee2e

// Real-execution scenarios for the Tier 3 live e2e suite. See doc.go for
// the package design, safety rules, and how to run the suite.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/internal/app"
	"github.com/yasindce1998/redhands/internal/binaries"
	"github.com/yasindce1998/redhands/internal/registry"
	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

// scenarioTimeout bounds each tools/call scenario (the executor's own
// per-binary timeout is tighter still; this is the outer belt).
const scenarioTimeout = 2 * time.Minute

// harness is a fully wired in-process RedHands server: the same
// executor, middleware, stores, registry, and campaign wiring as
// cmd/redhands, minus transports and plugins. Tests drive it with
// HandleRawContext JSON-RPC requests, exactly like a real client.
type harness struct {
	srv       *mcp.Server
	db        *targetdb.Store
	auditPath string
	dir       string
}

// newHarness builds the real server stack over a temp directory. The
// BinaryExecutor allowlist comes from binaries.Discover() (PATH lookup at
// test time), so a binary that is not installed simply never executes —
// tests gate on requireBinary before calling the tools that need it.
func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	cfg := &config.Config{
		Timeout:             90 * time.Second,
		MaxOutputBytes:      10 << 20,
		RateLimit:           1000, // no rate-limit interference in tests
		RateBurst:           1000,
		CacheTTL:            time.Minute,
		CacheMaxSize:        100,
		AuditFile:           filepath.Join(dir, "audit.jsonl"),
		MaxConcurrent:       8,
		MaxQueued:           32,
		WorkflowTimeout:     5 * time.Minute,
		// Approval posture of an operator who reviewed the scenario
		// tools: RegisterTool defaults every tool to the conservative
		// policy (approval required) and builtinPolicies exempts the
		// read-only ones; the executing tools below are explicitly
		// approved, exactly like a real REDHANDS_APPROVED_TOOLS setup.
		ApprovedTools: []string{
			"barzakh_corpus", "barzakh_scan", "barzakh_validate",
			"nmap_port_scan", "nmap_service_detect", "nuclei_scan",
			"telecom_firmware_analyze", "telecom_doctor",
			"kubedagger_k8s_discover",
		},
		TargetDBFile:        filepath.Join(dir, "targetdb", "targets.json"),
		EngagementDir:       filepath.Join(dir, "engagements"),
		LootDir:             filepath.Join(dir, "loot"),
		EvidenceDir:         filepath.Join(dir, "evidence"),
		WorkflowStateDir:    filepath.Join(dir, "state"),
		WorkflowTemplateDir: filepath.Join(dir, "templates"),
		WorkflowMaxParallel: 2,
	}

	executorAllowed := binaries.Discover()
	execr := executor.New(executor.Config{
		Timeout:         int64(cfg.Timeout.Seconds()),
		AllowedBinaries: executorAllowed,
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})
	procMgr := executor.NewBackgroundManager(executor.Config{
		AllowedBinaries: executorAllowed,
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})
	t.Cleanup(procMgr.StopAll)

	auditLogger, err := audit.NewFileLogger(cfg.AuditFile)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	stores, err := app.InitStores(cfg)
	if err != nil {
		t.Fatalf("stores: %v", err)
	}

	srv := mcp.NewServer("redhands-e2e", "test")

	// The real middleware chain: audit (to a temp file), no auth
	// (mode "none"), generous rate limits, engagement scope middleware
	// (no active engagement → everything in scope), approval gates, and
	// the concurrency limiter.
	app.SetupMiddleware(srv, cfg, auditLogger, auth.Config{Mode: "none"}, stores.EngMgr)
	app.SetupWorkflow(srv)
	campaignEngine := app.SetupCampaign(srv, cfg, stores.TargetDB, stores.EngMgr)

	// The real registry: every toolset with its real constructors and
	// builtin tool policies, exactly as cmd/redhands registers them.
	registry.RegisterAll(srv, &registry.Deps{
		Exec:        execr,
		Cfg:         cfg,
		TargetDB:    stores.TargetDB,
		Graph:       stores.Graph,
		EngMgr:      stores.EngMgr,
		Loot:        stores.Loot,
		CredStore:   stores.CredStore,
		Evidence:    stores.Evidence,
		ProcMgr:     procMgr,
		CampaignEng: campaignEngine,
	})

	return &harness{srv: srv, db: stores.TargetDB, auditPath: cfg.AuditFile, dir: dir}
}

// jsonrpcResponse is the subset of the JSON-RPC envelope the tests assert on.
type jsonrpcResponse struct {
	Result *struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// callToolRaw issues a tools/call JSON-RPC request through the full server
// stack and returns the first text block plus the isError flag.
func (h *harness) callToolRaw(ctx context.Context, t *testing.T, tool string, args any) (string, bool) {
	t.Helper()
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshaling arguments for %s: %v", tool, err)
	}
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": json.RawMessage(rawArgs),
		},
	})
	if err != nil {
		t.Fatalf("marshaling request for %s: %v", tool, err)
	}
	respBytes := h.srv.HandleRawContext(ctx, req)
	var resp jsonrpcResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("tools/call %s: unparsable JSON-RPC response: %v\n%s", tool, err, respBytes)
	}
	if resp.Error != nil {
		t.Fatalf("tools/call %s: JSON-RPC error %d: %s", tool, resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil || len(resp.Result.Content) == 0 {
		t.Fatalf("tools/call %s: response carries no content: %s", tool, respBytes)
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

// callTool asserts the tool succeeded and returns its first text block.
func (h *harness) callTool(ctx context.Context, t *testing.T, tool string, args any) string {
	t.Helper()
	text, isErr := h.callToolRaw(ctx, t, tool, args)
	if isErr {
		t.Fatalf("tool %s returned an error result:\n%s", tool, text)
	}
	return text
}

// campaignResult is the WorkflowResult shape returned by campaign/run.
type campaignResult struct {
	WorkflowID string `json:"workflow_id"`
	Status     string `json:"status"`
	Success    bool   `json:"success"`
	Steps      []struct {
		Tool     string `json:"tool"`
		ID       string `json:"id,omitempty"`
		Success  bool   `json:"success"`
		Skipped  bool   `json:"skipped,omitempty"`
		Text     string `json:"text"`
		Recorded int    `json:"recorded,omitempty"`
	} `json:"steps"`
}

// campaignRun issues a campaign/run JSON-RPC request (the same method the
// CLI and campaign_start tool delegate to) and asserts it returned a
// WorkflowResult, not a JSON-RPC error.
func (h *harness) campaignRun(ctx context.Context, t *testing.T, params string) campaignResult {
	t.Helper()
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"campaign/run","params":%s}`, params)
	respBytes := h.srv.HandleRawContext(ctx, json.RawMessage(req))
	var resp struct {
		Result  *campaignResult `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("campaign/run: unparsable JSON-RPC response: %v\n%s", err, respBytes)
	}
	if resp.Error != nil {
		t.Fatalf("campaign/run: JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatalf("campaign/run: no result object: %s", respBytes)
	}
	return *resp.Result
}

// requireBinary skips the test when the named binary is not on PATH,
// mirroring tools/livecheck's discovery pattern. The suite is safe to run
// on any machine; CI installs the binaries via scripts/dependencies.py.
func requireBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("binary %s not on PATH; install it (python3 scripts/dependencies.py install %s) to run this live e2e scenario here", name, name)
	}
	return path
}

// auditEvent mirrors the audit log's JSONL record (pkg/audit.AuditEvent).
type auditEvent struct {
	Action string `json:"action"`
	Tool   string `json:"tool"`
	Result string `json:"result"`
}

// auditToolCalls returns the set of tools that produced tools/call audit
// events so far. The file logger drains asynchronously, so callers poll
// with waitFor.
func (h *harness) auditToolCalls(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(h.auditPath)
	if err != nil {
		return nil
	}
	called := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev auditEvent
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Action == "tools/call" {
			called[ev.Tool] = true
		}
	}
	return called
}

// waitFor polls cond until it holds or the bounded deadline (2s) expires;
// the audit logger writes asynchronously, so this replaces sleeps.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// serveLocalTCP starts a test-owned TCP listener on 127.0.0.1:0 that
// answers every connection with a minimal HTTP response. It returns the
// port; only the test itself ever connects to it.
func serveLocalTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on 127.0.0.1:0: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				// Drain whatever the prober sends (bounded), then
				// answer with a tiny valid HTTP response so nmap's
				// NULL and GET probes both see a service.
				buf := make([]byte, 512)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: redhands-e2e\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return port
}

// serveLocalHTTP starts a test-owned HTTP server whose every response
// carries the marker header and body the nuclei template matches on.
func serveLocalHTTP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RedHands-E2E", "local-marker")
		_, _ = w.Write([]byte("redhands-e2e-marker-7f3a"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fencedJSON extracts the first ```json fenced block from a tool's
// markdown output (the wrapper output convention; mirrors
// workflow.StructuredFromText for test-side assertions).
func fencedJSON(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "```json\n")
	if i < 0 {
		t.Fatalf("no ```json fenced block in tool output:\n%s", truncateForTest(text))
	}
	rest := text[i+len("```json\n"):]
	j := strings.Index(rest, "\n```")
	if j < 0 {
		t.Fatalf("unterminated ```json fenced block in tool output:\n%s", truncateForTest(text))
	}
	return strings.TrimSpace(rest[:j])
}

func truncateForTest(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "\n...[truncated]"
	}
	return s
}
