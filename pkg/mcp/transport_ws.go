package mcp

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	wsGUID        = "258EAFA5-E914-47DA-95CA-5AB0DC85B11B"
	wsOpText      = 1
	wsOpClose     = 8
	wsOpPing      = 9
	wsOpPong      = 10
	wsMaskBit     = 0x80
	wsFinBit      = 0x80
	wsMaxPayload  = 10 * 1024 * 1024
)

type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

func (s *Server) ServeWebSocket(ctx context.Context, addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgradeWebSocket(w, r)
		if err != nil {
			log.Printf("ws: upgrade failed: %v", err)
			return
		}
		defer conn.conn.Close()

		s.handleWSConn(ctx, conn)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","transport":"ws"}`)
	})

	server := &http.Server{
		Addr:        addr,
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutCtx)
	}()

	log.Printf("WebSocket transport listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("ws server: %w", err)
	}
	return nil
}

func (s *Server) handleWSConn(ctx context.Context, ws *wsConn) {
	for {
		select {
		case <-ctx.Done():
			wsWriteClose(ws, 1001, "server shutting down")
			return
		default:
		}

		opcode, payload, err := wsReadFrame(ws)
		if err != nil {
			if err != io.EOF {
				log.Printf("ws: read error: %v", err)
			}
			return
		}

		switch opcode {
		case wsOpClose:
			wsWriteClose(ws, 1000, "")
			return
		case wsOpPing:
			wsWriteFrame(ws, wsOpPong, payload)
			continue
		case wsOpPong:
			continue
		case wsOpText:
			// Process JSON-RPC
		default:
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			resp := s.errorResponse(nil, ErrCodeParse, "parse error")
			data, _ := json.Marshal(resp)
			wsWriteFrame(ws, wsOpText, data)
			continue
		}

		if req.JSONRPC != JSONRPCVersion {
			resp := s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid jsonrpc version")
			data, _ := json.Marshal(resp)
			wsWriteFrame(ws, wsOpText, data)
			continue
		}

		resp := s.handleRequest(ctx, &req)
		if resp != nil {
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("ws: marshal error: %v", err)
				continue
			}
			if err := wsWriteFrame(ws, wsOpText, data); err != nil {
				log.Printf("ws: write error: %v", err)
				return
			}
		}
	}
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return nil, fmt.Errorf("missing Upgrade: websocket header")
	}

	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "missing Connection: Upgrade", http.StatusBadRequest)
		return nil, fmt.Errorf("missing Connection: Upgrade header")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	// Compute accept key
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return nil, fmt.Errorf("http.Hijacker not supported")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	// Write HTTP 101 response
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	if _, err := bufrw.WriteString(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade response: %w", err)
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("flush upgrade response: %w", err)
	}

	return &wsConn{conn: conn, reader: bufrw.Reader}, nil
}

func wsReadFrame(ws *wsConn) (byte, []byte, error) {
	// Read first two bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.reader, header); err != nil {
		return 0, nil, err
	}

	opcode := header[0] & 0x0F
	masked := (header[1] & wsMaskBit) != 0
	length := uint64(header[1] & 0x7F)

	// Extended payload length
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(ws.reader, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(ws.reader, ext); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > wsMaxPayload {
		return 0, nil, fmt.Errorf("payload too large: %d", length)
	}

	// Read masking key
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	// Read payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(ws.reader, payload); err != nil {
		return 0, nil, err
	}

	// Unmask
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func wsWriteFrame(ws *wsConn, opcode byte, payload []byte) error {
	length := len(payload)
	var header []byte

	if length <= 125 {
		header = []byte{wsFinBit | opcode, byte(length)}
	} else if length <= 65535 {
		header = make([]byte, 4)
		header[0] = wsFinBit | opcode
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(length))
	} else {
		header = make([]byte, 10)
		header[0] = wsFinBit | opcode
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	if _, err := ws.conn.Write(header); err != nil {
		return err
	}
	if _, err := ws.conn.Write(payload); err != nil {
		return err
	}
	return nil
}

func wsWriteClose(ws *wsConn, code uint16, reason string) {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)
	wsWriteFrame(ws, wsOpClose, payload)
}
