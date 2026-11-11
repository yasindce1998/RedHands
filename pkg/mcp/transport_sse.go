package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type sseClient struct {
	requests sync.Mutex
	events   chan []byte
	done     chan struct{}
	identity string
	ctx      context.Context
}

func (s *Server) ServeSSE(ctx context.Context, addr string) error {
	return s.ServeSSEWithOptions(ctx, addr, HTTPOptions{})
}

func (s *Server) ServeSSEWithHandler(ctx context.Context, addr string, check func(*http.Request) (context.Context, error)) error {
	return s.ServeSSEWithOptions(ctx, addr, HTTPOptions{AuthCheck: check})
}

func (s *Server) ServeSSEWithOptions(ctx context.Context, addr string, opts HTTPOptions) error {
	return serveHTTP(ctx, addr, s.SSEHandler(ctx, opts), opts)
}

// SSEHandler serves bounded JSON-RPC requests with unguessable session IDs.
func (s *Server) SSEHandler(ctx context.Context, opts HTTPOptions) http.Handler {
	var mu sync.RWMutex
	clients := make(map[string]*sseClient)
	identity := func(ctx context.Context) string {
		if opts.Identity != nil {
			return opts.Identity(ctx)
		}
		return ""
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		reqCtx, ok := checkHTTPRequest(w, r, opts)
		if !ok {
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}
		id := hex.EncodeToString(token[:])
		sessionCtx, cancelSession := context.WithCancel(reqCtx)
		defer cancelSession()
		client := &sseClient{events: make(chan []byte, 64), done: make(chan struct{}), identity: identity(reqCtx), ctx: sessionCtx}
		mu.Lock()
		if len(clients) >= 256 {
			mu.Unlock()
			http.Error(w, "too many sessions", http.StatusServiceUnavailable)
			return
		}
		clients[id] = client
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(clients, id)
			mu.Unlock()
			close(client.done)
		}()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Client-ID", id)
		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message?clientId=%s\n\n", id)
		flusher.Flush()
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		write := func(text string) bool {
			controller := http.NewResponseController(w)
			_ = controller.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.WriteString(w, text); err != nil {
				return false
			}
			if err := controller.Flush(); err != nil {
				return false
			}
			_ = controller.SetWriteDeadline(time.Time{})
			return true
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.Context().Done():
				return
			case <-heartbeat.C:
				if !write(": keepalive\n\n") {
					return
				}
			case data := <-client.events:
				if !write(fmt.Sprintf("event: message\ndata: %s\n\n", data)) {
					return
				}
			}
		}
	})
	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		reqCtx, ok := checkHTTPRequest(w, r, opts)
		if !ok {
			return
		}
		mu.RLock()
		client, ok := clients[r.URL.Query().Get("clientId")]
		mu.RUnlock()
		if !ok || client.identity != identity(reqCtx) {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		reqCtx, cancel := context.WithCancel(reqCtx)
		defer cancel()
		stop := context.AfterFunc(client.ctx, cancel)
		defer stop()
		if !client.requests.TryLock() {
			http.Error(w, "session already executing a request", http.StatusTooManyRequests)
			return
		}
		defer client.requests.Unlock()
		select {
		case <-client.done:
			http.Error(w, "session disconnected", http.StatusGone)
			return
		default:
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		// Serialize execution per session and check capacity before mutations.
		if len(client.events) == cap(client.events) {
			http.Error(w, "session response queue full", http.StatusServiceUnavailable)
			return
		}
		response := s.HandleRawContext(reqCtx, json.RawMessage(body))
		if response != nil {
			select {
			case client.events <- response:
			case <-client.done:
				return
			case <-reqCtx.Done():
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := checkHTTPRequest(w, r, opts); !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","transport":"sse"}`)
	})
	return mux
}
