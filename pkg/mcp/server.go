package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// WorkflowRunner executes a workflow from raw JSON params.
type WorkflowRunner interface {
	RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
}

// ReportGenerator generates a report from raw JSON params.
type ReportGenerator interface {
	GenerateFromJSON(data json.RawMessage) (string, error)
}

type Server struct {
	name        string
	version     string
	tools       map[string]Tool
	toolOrder   []string
	middlewares []Middleware
	initialized bool
	mu          sync.RWMutex
	workflow    WorkflowRunner
	reporter   ReportGenerator
}

func NewServer(name, version string) *Server {
	return &Server{
		name:    name,
		version: version,
		tools:   make(map[string]Tool),
	}
}

func (s *Server) RegisterTool(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[t.Name()] = t
	s.toolOrder = append(s.toolOrder, t.Name())
}

func (s *Server) Use(m Middleware) {
	s.middlewares = append(s.middlewares, m)
}

func (s *Server) GetTool(name string) (Tool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tools[name]
	return t, ok
}

func (s *Server) SetWorkflowRunner(w WorkflowRunner) {
	s.workflow = w
}

func (s *Server) SetReportGenerator(r ReportGenerator) {
	s.reporter = r
}

func (s *Server) ServeStdio(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return s.serve(ctx, os.Stdin, os.Stdout)
}

func (s *Server) serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := s.errorResponse(nil, ErrCodeParse, "parse error")
			s.writeResponse(w, resp)
			continue
		}

		if req.JSONRPC != JSONRPCVersion {
			resp := s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid jsonrpc version")
			s.writeResponse(w, resp)
			continue
		}

		resp := s.handleRequest(ctx, &req)
		if resp != nil {
			s.writeResponse(w, resp)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	return nil
}

func (s *Server) writeResponse(w io.Writer, resp *JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("failed to marshal response: %v", err)
		return
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}
