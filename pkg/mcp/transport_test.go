package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestSSEBodyLimitAndOrigin(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(srv.SSEHandler(ctx, mcp.HTTPOptions{}))
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/sse", nil)
	request.Header.Set("Origin", "https://untrusted.test")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("foreign Origin accepted")
	}
	stream, err := http.Get(server.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Body.Close() }()
	reader := bufio.NewReader(stream.Body)
	_, _ = reader.ReadString('\n')
	line, _ := reader.ReadString('\n')
	endpoint := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
	id := stream.Header.Get("X-Client-ID")
	if len(id) != 64 || strings.HasPrefix(id, "client-") {
		t.Fatalf("weak session ID %q", id)
	}
	response, err = http.Post(server.URL+endpoint, "application/json", strings.NewReader(strings.Repeat(" ", mcp.MaxRequestBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body status: %d", response.StatusCode)
	}
}

func TestWebSocketAuthenticationAndContext(t *testing.T) {
	ac := auth.Config{Mode: "apikey", APIKey: "test-secret"}
	srv := mcp.NewServer("test", "1")
	srv.SetRequestCheck(func(ctx context.Context) error { return auth.CheckContext(ac, ctx) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(srv.WebSocketHandler(ctx, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)}))
	defer server.Close()
	resp, err := http.Get(server.URL + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("unauthenticated WebSocket accepted")
	}
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: "+strings.TrimPrefix(server.URL, "http://")+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-API-Key: test-secret\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	upgrade, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upgrade.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status: %d", upgrade.StatusCode)
	}
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("authentication required")) || !bytes.Contains(body, []byte(`"result"`)) {
		t.Fatalf("auth context lost: %s", body)
	}
}

func TestTCPContextAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport, err := mcp.NewTCPTransportWithOptions(ctx, "127.0.0.1:0", func(ctx context.Context, raw json.RawMessage) json.RawMessage {
		identity, _ := ctx.Value(auth.ContextKeyIdentity).(string)
		if identity != "test-peer" {
			return json.RawMessage(`{"error":"identity lost"}`)
		}
		return json.RawMessage(`{"ok":true}`)
	}, mcp.TCPOptions{Authenticate: func(ctx context.Context, _ net.Conn) (context.Context, error) {
		return auth.InjectAuthContext(ctx, "test-peer"), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.Close() }()
	done := make(chan error, 1)
	go func() { done <- transport.Serve() }()
	conn, err := net.DialTimeout("tcp", transport.Addr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte(`{}`)
	if err := binary.Write(conn, binary.BigEndian, uint32(len(payload))); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != `{"ok":true}` {
		t.Fatalf("response: %s", response)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
}

type concurrentTool struct{}

func (concurrentTool) Name() string                 { return "test" }
func (concurrentTool) Description() string          { return "test" }
func (concurrentTool) InputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (concurrentTool) Execute(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{}, nil
}

func TestConcurrentRegistryReload(t *testing.T) {
	srv := mcp.NewServer("test", "1")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				srv.RegisterTool(concurrentTool{})
				srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
				_, _ = srv.ExecuteTool(context.Background(), "test", json.RawMessage(`{}`))
				srv.UnregisterTool("test")
			}
		})
	}
	wg.Wait()
}
