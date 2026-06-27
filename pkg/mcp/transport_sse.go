package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type sseClient struct {
	id     string
	events chan []byte
	done   chan struct{}
}

func (s *Server) ServeSSE(ctx context.Context, addr string) error {
	var clientID atomic.Uint64
	var mu sync.RWMutex
	clients := make(map[string]*sseClient)

	mux := http.NewServeMux()

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		id := fmt.Sprintf("client-%d", clientID.Add(1))
		client := &sseClient{
			id:     id,
			events: make(chan []byte, 64),
			done:   make(chan struct{}),
		}

		mu.Lock()
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
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Client-ID", id)

		// Send endpoint event so client knows where to POST
		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message?clientId=%s\n\n", id)
		flusher.Flush()

		for {
			select {
			case <-ctx.Done():
				return
			case <-r.Context().Done():
				return
			case data := <-client.events:
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientId := r.URL.Query().Get("clientId")
		if clientId == "" {
			http.Error(w, "missing clientId parameter", http.StatusBadRequest)
			return
		}

		mu.RLock()
		client, ok := clients[clientId]
		mu.RUnlock()
		if !ok {
			http.Error(w, "unknown client", http.StatusNotFound)
			return
		}

		scanner := bufio.NewScanner(r.Body)
		scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var req JSONRPCRequest
			if err := json.Unmarshal(line, &req); err != nil {
				resp := s.errorResponse(nil, ErrCodeParse, "parse error")
				data, _ := json.Marshal(resp)
				select {
				case client.events <- data:
				default:
				}
				continue
			}

			if req.JSONRPC != JSONRPCVersion {
				resp := s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid jsonrpc version")
				data, _ := json.Marshal(resp)
				select {
				case client.events <- data:
				default:
				}
				continue
			}

			resp := s.handleRequest(r.Context(), &req)
			if resp != nil {
				data, err := json.Marshal(resp)
				if err != nil {
					log.Printf("sse: failed to marshal response: %v", err)
					continue
				}
				select {
				case client.events <- data:
				default:
					log.Printf("sse: client %s event buffer full, dropping message", clientId)
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("sse: scanner error for client %s: %v", clientId, err)
		}

		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"status":"accepted"}`)
	})

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","transport":"sse"}`)
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE needs no write timeout
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutCtx)
	}()

	log.Printf("SSE transport listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("sse server: %w", err)
	}
	return nil
}

// ServeSSEWithHandler is like ServeSSE but also accepts a pre-request handler
// for authentication checks. The handler can inspect the request and return
// a modified context or an error to reject the connection.
func (s *Server) ServeSSEWithHandler(ctx context.Context, addr string, authCheck func(r *http.Request) (context.Context, error)) error {
	var clientID atomic.Uint64
	var mu sync.RWMutex
	clients := make(map[string]*sseClient)

	mux := http.NewServeMux()

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if authCheck != nil {
			if _, err := authCheck(r); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		id := fmt.Sprintf("client-%d", clientID.Add(1))
		client := &sseClient{
			id:     id,
			events: make(chan []byte, 64),
			done:   make(chan struct{}),
		}

		mu.Lock()
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
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Client-ID", id)

		_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message?clientId=%s\n\n", id)
		flusher.Flush()

		for {
			select {
			case <-ctx.Done():
				return
			case <-r.Context().Done():
				return
			case data := <-client.events:
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	})

	mux.HandleFunc("/message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		reqCtx := r.Context()
		if authCheck != nil {
			newCtx, err := authCheck(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			reqCtx = newCtx
		}

		clientId := r.URL.Query().Get("clientId")
		if clientId == "" {
			http.Error(w, "missing clientId parameter", http.StatusBadRequest)
			return
		}

		mu.RLock()
		client, ok := clients[clientId]
		mu.RUnlock()
		if !ok {
			http.Error(w, "unknown client", http.StatusNotFound)
			return
		}

		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)

		var req JSONRPCRequest
		if err := json.Unmarshal(body.Bytes(), &req); err != nil {
			resp := s.errorResponse(nil, ErrCodeParse, "parse error")
			data, _ := json.Marshal(resp)
			select {
			case client.events <- data:
			default:
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}

		if req.JSONRPC != JSONRPCVersion {
			resp := s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid jsonrpc version")
			data, _ := json.Marshal(resp)
			select {
			case client.events <- data:
			default:
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}

		resp := s.handleRequest(reqCtx, &req)
		if resp != nil {
			data, err := json.Marshal(resp)
			if err == nil {
				select {
				case client.events <- data:
				default:
				}
			}
		}

		w.WriteHeader(http.StatusAccepted)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","transport":"sse"}`)
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutCtx)
	}()

	log.Printf("SSE transport listening on %s (with auth)", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("sse server: %w", err)
	}
	return nil
}
