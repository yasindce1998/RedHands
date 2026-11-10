package mcp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type TCPTransport struct {
	listener       net.Listener
	mu             sync.Mutex
	conns          map[net.Conn]struct{}
	done           chan struct{}
	once           sync.Once
	ctx            context.Context
	contextHandler func(context.Context, json.RawMessage) json.RawMessage
	authenticate   func(context.Context, net.Conn) (context.Context, error)
}

type TCPOptions struct {
	TLSConfig    *tls.Config
	Authenticate func(context.Context, net.Conn) (context.Context, error)
}

func NewTCPTransport(addr string, handler func(json.RawMessage) json.RawMessage) (*TCPTransport, error) {
	return NewTCPTransportWithOptions(context.Background(), addr, func(_ context.Context, msg json.RawMessage) json.RawMessage { return handler(msg) }, TCPOptions{})
}

func NewTCPTransportWithOptions(ctx context.Context, addr string, handler func(context.Context, json.RawMessage) json.RawMessage, opts TCPOptions) (*TCPTransport, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen: %w", err)
	}
	if opts.TLSConfig != nil {
		ln = tls.NewListener(ln, opts.TLSConfig)
	}

	return &TCPTransport{
		listener:       ln,
		contextHandler: handler,
		authenticate:   opts.Authenticate,
		ctx:            ctx,
		conns:          make(map[net.Conn]struct{}),
		done:           make(chan struct{}),
	}, nil
}

func (t *TCPTransport) Addr() string {
	return t.listener.Addr().String()
}

func (t *TCPTransport) Serve() error {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.done:
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}

		t.mu.Lock()
		select {
		case <-t.done:
			t.mu.Unlock()
			_ = conn.Close()
			return nil
		default:
		}
		if len(t.conns) >= 256 {
			t.mu.Unlock()
			_ = conn.Close()
			continue
		}
		t.conns[conn] = struct{}{}
		t.mu.Unlock()

		go t.handleConn(conn)
	}
}

func (t *TCPTransport) Close() error {
	var err error
	t.once.Do(func() {
		close(t.done)
		err = t.listener.Close()
		t.mu.Lock()
		defer t.mu.Unlock()
		for c := range t.conns {
			_ = c.Close()
		}
	})
	return err
}

func (t *TCPTransport) handleConn(conn net.Conn) {
	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	defer func() {
		_ = conn.Close()
		t.mu.Lock()
		delete(t.conns, conn)
		t.mu.Unlock()
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if t.authenticate != nil {
		var err error
		ctx, err = t.authenticate(ctx, conn)
		if err != nil {
			return
		}
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_ = conn.SetWriteDeadline(time.Time{})
		msg, err := readFrame(conn)
		if err != nil {
			return
		}

		resp := t.contextHandler(ctx, msg)
		if resp == nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

		if err := writeFrame(conn, resp); err != nil {
			return
		}
	}
}

func readFrame(r io.Reader) (json.RawMessage, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length > 16*1024*1024 {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return json.RawMessage(buf), nil
}

func writeFrame(w io.Writer, data json.RawMessage) error {
	length := uint32(len(data))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}
