package mcp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type TCPTransport struct {
	listener net.Listener
	handler  func(json.RawMessage) json.RawMessage
	mu       sync.Mutex
	conns    []net.Conn
	done     chan struct{}
}

func NewTCPTransport(addr string, handler func(json.RawMessage) json.RawMessage) (*TCPTransport, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen: %w", err)
	}

	return &TCPTransport{
		listener: ln,
		handler:  handler,
		done:     make(chan struct{}),
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
		t.conns = append(t.conns, conn)
		t.mu.Unlock()

		go t.handleConn(conn)
	}
}

func (t *TCPTransport) Close() error {
	close(t.done)

	t.mu.Lock()
	for _, c := range t.conns {
		c.Close()
	}
	t.conns = nil
	t.mu.Unlock()

	return t.listener.Close()
}

func (t *TCPTransport) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		msg, err := readFrame(conn)
		if err != nil {
			return
		}

		resp := t.handler(msg)

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
