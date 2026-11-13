package mcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

type echoTool struct{}

func (echoTool) Name() string                 { return "echo_tool" }
func (echoTool) Description() string          { return "echo" }
func (echoTool) InputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (echoTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, err
	}
	return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "echo: " + input.Msg}}}, nil
}

func newTestServer() *mcp.Server {
	srv := mcp.NewServer("test-server", "1.0.0")
	if err := srv.RegisterTool(echoTool{}); err != nil {
		panic(err)
	}
	return srv
}

// postMCP sends a POST to the streamable HTTP endpoint with modern headers.
func postMCP(t *testing.T, url string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeRPC(t *testing.T, resp *http.Response) (status int, rpc struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}) {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rpc); err != nil {
		t.Fatalf("response is not a JSON-RPC object: %s", data)
	}
	return resp.StatusCode, rpc
}

func mustHeaders() map[string]string {
	return map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/list",
	}
}

// --- Handler-level (protocol surface) tests ---

func TestServerDiscoverResult(t *testing.T) {
	srv := newTestServer()
	raw := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"server/discover"}`))
	var resp struct {
		Result struct {
			ProtocolVersion  string                         `json:"protocolVersion"`
			ServerInfo       struct{ Name, Version string } `json:"serverInfo"`
			ProtocolVersions []string                       `json:"protocolVersions"`
			Capabilities     struct {
				Tools      map[string]any             `json:"tools"`
				Extensions map[string]json.RawMessage `json:"extensions"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("parse discover response: %v", err)
	}
	if resp.Result.ProtocolVersion != mcp.ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", resp.Result.ProtocolVersion, mcp.ProtocolVersion)
	}
	if resp.Result.ServerInfo.Name != "test-server" {
		t.Errorf("serverInfo.name = %q", resp.Result.ServerInfo.Name)
	}
	want := map[string]bool{mcp.ProtocolVersion: false, "2025-03-26": false, "2024-11-05": false}
	for _, v := range resp.Result.ProtocolVersions {
		if _, ok := want[v]; ok {
			want[v] = true
		}
	}
	for v, seen := range want {
		if !seen {
			t.Errorf("protocolVersions missing %q: %v", v, resp.Result.ProtocolVersions)
		}
	}
	if resp.Result.Capabilities.Tools == nil {
		t.Error("discover result must advertise the tools capability")
	}
	if len(resp.Result.Capabilities.Extensions) != 0 {
		t.Errorf("extensions must be omitted when none exist: %v", resp.Result.Capabilities.Extensions)
	}
}

func TestRequestMetaUnsupportedVersionRaw(t *testing.T) {
	srv := newTestServer()
	raw := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}`))
	var resp struct {
		Error *struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != mcp.ErrCodeUnsupportedProtocolVersion {
		t.Fatalf("expected -32022, got %s", raw)
	}
	supported, _ := resp.Error.Data["supported"].([]any)
	if len(supported) != 1 || supported[0] != mcp.ProtocolVersion {
		t.Errorf("data.supported = %v, want [%q]", supported, mcp.ProtocolVersion)
	}
	if resp.Error.Data["requested"] != "1999-01-01" {
		t.Errorf("data.requested = %v", resp.Error.Data["requested"])
	}
}

func TestRequestMetaLegacyVersionsAccepted(t *testing.T) {
	srv := newTestServer()
	for _, version := range []string{"2024-11-05", "2025-03-26", mcp.ProtocolVersion} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + version + `"}}}`
		raw := srv.HandleRaw(json.RawMessage(body))
		if !strings.Contains(string(raw), `"tools"`) {
			t.Errorf("version %s rejected: %s", version, raw)
		}
	}
	// No _meta at all: legacy-era request, served without validation.
	raw := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if !strings.Contains(string(raw), `"tools"`) {
		t.Errorf("legacy request without _meta rejected: %s", raw)
	}
}

func TestToolsListCarriesTTL(t *testing.T) {
	srv := newTestServer()
	raw := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	var resp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
			TTLMs int                     `json:"ttlMs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.TTLMs != 300000 {
		t.Errorf("ttlMs = %d, want 300000", resp.Result.TTLMs)
	}
}

func TestInitializeEchoesSupportedVersion(t *testing.T) {
	srv := newTestServer()
	raw := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	var resp struct {
		Result struct {
			ProtocolVersion  string   `json:"protocolVersion"`
			ProtocolVersions []string `json:"protocolVersions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.ProtocolVersion != "2025-03-26" {
		t.Errorf("negotiated protocolVersion = %q, want echo of 2025-03-26", resp.Result.ProtocolVersion)
	}
	found := false
	for _, v := range resp.Result.ProtocolVersions {
		if v == mcp.ProtocolVersion {
			found = true
		}
	}
	if !found {
		t.Errorf("initialize result must list %q in protocolVersions: %v", mcp.ProtocolVersion, resp.Result.ProtocolVersions)
	}
}

// --- RegisterTool schema hygiene ---

type schemaTool struct {
	schema string
}

func (s schemaTool) Name() string                 { return "schema_tool" }
func (s schemaTool) Description() string          { return "schema probe" }
func (s schemaTool) InputSchema() json.RawMessage { return json.RawMessage(s.schema) }
func (s schemaTool) Execute(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{}, nil
}

func TestRegisterToolSchemaValidation(t *testing.T) {
	cases := []struct {
		name    string
		schema  string
		wantErr bool
	}{
		{"no schema keyword", `{"type":"object"}`, false},
		{"empty schema", ``, false},
		{"2020-12 dialect", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`, false},
		{"draft-07 rejected", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`, true},
		{"non-object rejected", `[]`, true},
		{"scalar rejected", `5`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mcp.NewServer("test", "1")
			err := srv.RegisterTool(schemaTool{schema: tc.schema})
			if tc.wantErr && err == nil {
				t.Fatalf("schema %q accepted", tc.schema)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("schema %q rejected: %v", tc.schema, err)
			}
		})
	}
}

// --- Streamable HTTP transport tests ---

func newHTTPServer(t *testing.T, opts mcp.HTTPOptions) *httptest.Server {
	t.Helper()
	srv := newTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := httptest.NewServer(srv.StreamableHTTPHandler(ctx, mcp.DefaultHTTPPath, opts))
	t.Cleanup(server.Close)
	return server
}

func TestStreamableHTTPDiscover(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "server/discover",
	}, `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("status %d, error %+v", status, rpc.Error)
	}
	if !strings.Contains(string(rpc.Result), `"protocolVersions"`) {
		t.Errorf("discover result missing protocolVersions: %s", rpc.Result)
	}
}

func TestStreamableHTTPMissingRequiredHeaders(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	resp := postMCP(t, server.URL+"/mcp", map[string]string{"Mcp-Method": "tools/list"}, body)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("missing MCP-Protocol-Version: status %d, error %+v", status, rpc.Error)
	} else if !strings.Contains(rpc.Error.Message, "MCP-Protocol-Version") {
		t.Errorf("error message %q must name the missing header", rpc.Error.Message)
	}

	resp = postMCP(t, server.URL+"/mcp", map[string]string{"MCP-Protocol-Version": mcp.ProtocolVersion}, body)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("missing Mcp-Method: status %d, error %+v", status, rpc.Error)
	}

	callBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{"msg":"hi"}}}`
	resp = postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/call",
	}, callBody)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("missing Mcp-Name on tools/call: status %d, error %+v", status, rpc.Error)
	}
}

func TestStreamableHTTPHeaderBodyMismatch(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})

	// Mcp-Method differs from body method.
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/call",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("method mismatch: status %d, error %+v", status, rpc.Error)
	}

	// Mcp-Name differs from params.name.
	resp = postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "other_tool",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{"msg":"hi"}}}`)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("name mismatch: status %d, error %+v", status, rpc.Error)
	}

	// Header version differs from body _meta version (both supported).
	resp = postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/list",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2024-11-05"}}}`)
	if status, rpc := decodeRPC(t, resp); status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeHeaderMismatch {
		t.Errorf("version mismatch: status %d, error %+v", status, rpc.Error)
	}
}

func TestStreamableHTTPBase64EncodedName(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("echo_tool")) + "?="
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             encoded,
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{"msg":"hi"}}}`)
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("base64 sentinel name rejected: status %d, error %+v", status, rpc.Error)
	}
	if !strings.Contains(string(rpc.Result), "echo: hi") {
		t.Errorf("unexpected result: %s", rpc.Result)
	}
}

func TestStreamableHTTPMethodNotAllowed(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, server.URL+"/mcp", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want 405", method, resp.StatusCode)
		}
		if resp.Header.Get("Allow") != http.MethodPost {
			t.Errorf("%s Allow header = %q", method, resp.Header.Get("Allow"))
		}
	}
}

func TestStreamableHTTPNotificationAccepted(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "notifications/initialized",
	}, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status = %d, want 202", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	if len(data) != 0 {
		t.Errorf("notification response body must be empty, got %q", data)
	}
}

func TestStreamableHTTPUnknownMethodIs404(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "nonexistent/method",
	}, `{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}`)
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	if rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeMethodNotFound {
		t.Errorf("error = %+v, want -32601", rpc.Error)
	}
}

func TestStreamableHTTPBadOrigin(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Origin", "https://untrusted.test")
	req.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
	req.Header.Set("Mcp-Method", "tools/list")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin status = %d, want 403", resp.StatusCode)
	}
}

func TestStreamableHTTPAuthRequired(t *testing.T) {
	ac := auth.Config{Mode: "apikey", APIKey: "test-secret"}
	server := newHTTPServer(t, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)})
	resp := postMCP(t, server.URL+"/mcp", mustHeaders(), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing API key status = %d, want 401", resp.StatusCode)
	}
	// With the key the same request succeeds.
	headers := mustHeaders()
	headers["X-API-Key"] = "test-secret"
	resp = postMCP(t, server.URL+"/mcp", headers, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if status, rpc := decodeRPC(t, resp); status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("authenticated request: status %d, error %+v", status, rpc.Error)
	}
}

func TestStreamableHTTPUnsupportedVersion(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})

	// Unsupported version in the header.
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": "1999-01-01",
		"Mcp-Method":           "tools/list",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeUnsupportedProtocolVersion {
		t.Fatalf("header version: status %d, error %+v", status, rpc.Error)
	}
	if got, _ := rpc.Error.Data["supported"].([]any); len(got) != 1 || got[0] != mcp.ProtocolVersion {
		t.Errorf("header version: data.supported = %v", rpc.Error.Data["supported"])
	}

	// Unsupported version in the body _meta (headers valid).
	resp = postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/list",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}`)
	status, rpc = decodeRPC(t, resp)
	if status != http.StatusBadRequest || rpc.Error == nil || rpc.Error.Code != mcp.ErrCodeUnsupportedProtocolVersion {
		t.Fatalf("body version: status %d, error %+v", status, rpc.Error)
	}
	if rpc.Error.Data["requested"] != "1999-01-01" {
		t.Errorf("body version: data.requested = %v", rpc.Error.Data["requested"])
	}
}

func TestStreamableHTTPLegacyInitializeDualEra(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	// A legacy-era initialize (no _meta, legacy header version) still works
	// on the modern endpoint.
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": "2024-11-05",
		"Mcp-Method":           "initialize",
	}, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"legacy","version":"0.1"}}}`)
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("legacy initialize: status %d, error %+v", status, rpc.Error)
	}
	if !strings.Contains(string(rpc.Result), `"protocolVersion":"2024-11-05"`) {
		t.Errorf("legacy initialize result: %s", rpc.Result)
	}

	// And the modern era on the same endpoint: discover with matching _meta.
	resp = postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "server/discover",
	}, `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcp.ProtocolVersion+`","io.modelcontextprotocol/clientInfo":{"name":"modern","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{"extensions":{}}}}}`)
	status, rpc = decodeRPC(t, resp)
	if status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("modern discover: status %d, error %+v", status, rpc.Error)
	}
}

func TestStreamableHTTPToolsCallWithHeaders(t *testing.T) {
	server := newHTTPServer(t, mcp.HTTPOptions{})
	resp := postMCP(t, server.URL+"/mcp", map[string]string{
		"MCP-Protocol-Version": mcp.ProtocolVersion,
		"Mcp-Method":           "tools/call",
		"Mcp-Name":             "echo_tool",
	}, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{"msg":"hello"}}}`)
	status, rpc := decodeRPC(t, resp)
	if status != http.StatusOK || rpc.Error != nil {
		t.Fatalf("status %d, error %+v", status, rpc.Error)
	}
	if !strings.Contains(string(rpc.Result), "echo: hello") {
		t.Errorf("unexpected result: %s", rpc.Result)
	}
}
