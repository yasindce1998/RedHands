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
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// WorkflowRunner executes a workflow from raw JSON params.
type WorkflowRunner interface {
	RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
}

// CampaignEngine powers the multi-stage campaign methods: conditional and
// parallel step execution, checkpointing, resumption, and playbooks.
type CampaignEngine interface {
	RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
	StatusFromJSON(params json.RawMessage) (json.RawMessage, error)
	ListFromJSON(params json.RawMessage) (json.RawMessage, error)
	ResumeFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
	CancelFromJSON(params json.RawMessage) (json.RawMessage, error)
	TemplatesFromJSON(params json.RawMessage) (json.RawMessage, error)
	GetTemplateFromJSON(params json.RawMessage) (json.RawMessage, error)
	SaveTemplateFromJSON(params json.RawMessage) (json.RawMessage, error)
	// StartAsyncFromJSON is campaign/start's async path: it validates the
	// params, durably persists the initial running state, launches the
	// campaign in a background goroutine on the supplied context, and
	// returns the task id (= workflow id). alreadyRunning reports that a
	// campaign with the same id is in flight (idempotent re-start); the
	// caller answers with the live task instead of an error.
	StartAsyncFromJSON(ctx context.Context, params json.RawMessage) (taskID string, alreadyRunning bool, err error)
	// TaskUpdateFromJSON is the engine side of tasks/update: it records
	// client inputResponses on a paused campaign's pending approval
	// request. Unknown or stale keys are acknowledged and ignored.
	TaskUpdateFromJSON(params json.RawMessage) (json.RawMessage, error)
}

// ReportGenerator generates a report from raw JSON params.
type ReportGenerator interface {
	GenerateFromJSON(data json.RawMessage) (string, error)
}

type Server struct {
	name            string
	version         string
	tools           map[string]Tool
	policies        map[string]ToolPolicy
	toolOrder       []string
	middlewares     []Middleware
	mu              sync.RWMutex
	workflow        WorkflowRunner
	reporter        ReportGenerator
	requestCheck    func(context.Context) error
	workflowTimeout time.Duration
	campaign        CampaignEngine
}

func NewServer(name, version string) *Server {
	return &Server{
		name:            name,
		version:         version,
		tools:           make(map[string]Tool),
		policies:        make(map[string]ToolPolicy),
		workflowTimeout: 30 * time.Minute,
	}
}

// RegisterTool registers t and returns an error when the tool's input
// schema is malformed or declares an unsupported JSON Schema dialect.
// Schemas without a $schema keyword are accepted for backwards
// compatibility; when present, the keyword must name the 2020-12 draft.
// Callers that ignore the error skip registration of the rejected tool.
func (s *Server) RegisterTool(t Tool) error {
	if err := validateToolInputSchema(t.Name(), t.InputSchema()); err != nil {
		log.Printf("mcp: rejecting tool %q: %v", t.Name(), err)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name()]; !exists {
		s.toolOrder = append(s.toolOrder, t.Name())
	}
	s.tools[t.Name()] = t
	s.policies[t.Name()] = ConservativePolicy()
	return nil
}

// validateToolInputSchema enforces schema hygiene at registration time:
// InputSchema must be absent/null or a JSON object, and a declared
// $schema must be the JSON Schema 2020-12 dialect URI.
func validateToolInputSchema(tool string, schema json.RawMessage) error {
	trimmed := []byte(strings.TrimSpace(string(schema)))
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	var probe struct {
		Schema string `json:"$schema"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return fmt.Errorf("inputSchema must be a JSON object")
	}
	if probe.Schema == "" {
		return nil
	}
	if probe.Schema != JSONSchemaDialect202012 {
		return fmt.Errorf("inputSchema $schema must be %q, got %q", JSONSchemaDialect202012, probe.Schema)
	}
	return nil
}

func (s *Server) Use(m Middleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.middlewares = append(s.middlewares, m)
}

func (s *Server) UnregisterTool(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tools, name)
	delete(s.policies, name)
	s.toolOrder = slices.DeleteFunc(s.toolOrder, func(n string) bool { return n == name })
}

// SetRequestCheck protects all RPC methods, including workflows and reports.
// Configure it before starting any transports.
func (s *Server) SetRequestCheck(check func(context.Context) error) {
	s.requestCheck = check
}

// ExecuteTool is the single execution path for direct calls and workflow steps.
func (s *Server) ExecuteTool(ctx context.Context, name string, args json.RawMessage) (*ToolResult, error) {
	if s.requestCheck != nil {
		if err := s.requestCheck(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.RLock()
	tool, ok := s.tools[name]
	policy := s.policies[name]
	middlewares := slices.Clone(s.middlewares)
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(args, &object); err != nil || object == nil {
		return nil, fmt.Errorf("tool arguments must be a JSON object")
	}
	ctx = context.WithValue(ctx, toolPolicyContextKey{}, policy)
	return chainMiddleware(func(ctx context.Context, _ string, args json.RawMessage) (*ToolResult, error) {
		result, err := tool.Execute(ctx, args)
		if result == nil && err == nil {
			return nil, fmt.Errorf("tool %s returned no result", name)
		}
		return result, err
	}, middlewares)(ctx, name, args)
}

func (s *Server) SetWorkflowTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.workflowTimeout = timeout
	}
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

// SetCampaignEngine wires the multi-stage campaign methods.
func (s *Server) SetCampaignEngine(c CampaignEngine) {
	s.campaign = c
}

func (s *Server) SetReportGenerator(r ReportGenerator) {
	s.reporter = r
}

func (s *Server) ServeStdio(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
	defer stop()

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
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("reading stdin: %w", err)
	}

	return nil
}

func (s *Server) HandleRaw(msg json.RawMessage) json.RawMessage {
	return s.HandleRawContext(context.Background(), msg)
}

func (s *Server) HandleRawContext(ctx context.Context, msg json.RawMessage) json.RawMessage {
	var req JSONRPCRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		resp := s.errorResponse(nil, ErrCodeParse, "parse error")
		data, _ := json.Marshal(resp)
		return data
	}

	if req.JSONRPC != JSONRPCVersion {
		resp := s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid jsonrpc version")
		data, _ := json.Marshal(resp)
		return data
	}

	resp := s.handleRequest(ctx, &req)
	if resp == nil {
		return nil
	}
	data, _ := json.Marshal(resp)
	return data
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
