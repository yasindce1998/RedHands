package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if req.JSONRPC != JSONRPCVersion || req.Method == "" {
		return s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid JSON-RPC request")
	}
	if s.requestCheck != nil {
		if err := s.requestCheck(ctx); err != nil {
			if len(req.ID) == 0 {
				return nil
			}
			return s.errorResponse(req.ID, ErrCodeUnauthorized, err.Error())
		}
	}
	// Modern-era version negotiation: a request that carries _meta with a
	// protocol version must name one this server speaks. A request with no
	// _meta at all is legacy-era and is served without validation
	// (dual-era tolerance). Notifications cannot carry an error response,
	// so an unsupported version on an ID-less message is dropped silently.
	if meta, ok := ParseRequestMeta(req.Params); ok && meta.ProtocolVersion != "" && !protocolVersionSupported(meta.ProtocolVersion) {
		if len(req.ID) == 0 {
			return nil
		}
		return unsupportedProtocolVersionError(req.ID, meta.ProtocolVersion)
	}
	// JSON-RPC notifications execute without a response. Never emit ID-less replies.
	if len(req.ID) == 0 {
		if strings.HasPrefix(req.Method, "notifications/") {
			return nil
		}
		silent := *req
		silent.ID = json.RawMessage(`null`)
		_ = s.handleRequest(ctx, &silent)
		return nil
	}
	switch req.Method {
	case MethodInitialize:
		return s.handleInitialize(req)
	case MethodInitialized:
		// Legacy-era initialized notification. The server is stateless, so
		// there is no session state to flip; the notification is accepted.
		return nil
	case MethodServerDiscover:
		return s.handleServerDiscover(req)
	case MethodToolsList:
		return s.handleToolsList(req)
	case MethodToolsCall:
		return s.handleToolsCall(ctx, req)
	case MethodWorkflowRun:
		return s.handleWorkflowRun(ctx, req)
	case MethodCampaignRun:
		return s.handleCampaignRun(ctx, req)
	case MethodCampaignResume:
		if s.campaign == nil {
			return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
		}
		ctx, cancel := context.WithTimeout(ctx, s.workflowTimeout)
		defer cancel()
		result, err := s.campaign.ResumeFromJSON(ctx, req.Params)
		if err != nil {
			return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
		}
		return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(result)}
	case MethodCampaignStatus, MethodCampaignList, MethodCampaignCancel,
		MethodCampaignTemplates, MethodCampaignTemplateGet, MethodCampaignTemplateSave:
		return s.handleCampaignQuery(ctx, req)
	case MethodReportGenerate:
		return s.handleReportGenerate(req)
	case MethodPing:
		return s.successResponse(req.ID, struct{}{})
	default:
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func (s *Server) handleInitialize(req *JSONRPCRequest) *JSONRPCResponse {
	var params InitializeParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return s.errorResponse(req.ID, ErrCodeInvalidParams, "invalid initialize params")
		}
	}

	// Dual-era version negotiation: echo the client's revision when the
	// server speaks it, otherwise fall back to the legacy default.
	version := LegacyProtocolVersion2024
	if protocolVersionSupported(params.ProtocolVersion) {
		version = params.ProtocolVersion
	}

	result := InitializeResult{
		ProtocolVersion:  version,
		ProtocolVersions: SupportedProtocolVersions(),
		Capabilities: ServerCaps{
			Tools: &ToolsCap{ListChanged: false},
		},
		ServerInfo: ServerInfo{
			Name:    s.name,
			Version: s.version,
		},
	}

	return s.successResponse(req.ID, result)
}

// handleServerDiscover answers the stateless modern discovery request:
// no handshake, no session; the result names the server and every
// protocol revision it speaks.
func (s *Server) handleServerDiscover(req *JSONRPCRequest) *JSONRPCResponse {
	result := DiscoverResult{
		ProtocolVersion:  ProtocolVersion,
		ServerInfo:       ServerInfo{Name: s.name, Version: s.version},
		ProtocolVersions: SupportedProtocolVersions(),
		Capabilities: DiscoverCaps{
			Tools: &ToolsCap{},
			// Extensions are advertised only when they exist; none do yet,
			// so the map stays nil and the field is omitted.
		},
	}
	return s.successResponse(req.ID, result)
}

func (s *Server) handleToolsList(req *JSONRPCRequest) *JSONRPCResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tools := make([]ToolDef, 0, len(s.tools))
	for _, name := range s.toolOrder {
		t := s.tools[name]
		policy := s.policies[name]
		tools = append(tools, ToolDef{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.InputSchema(),
			Policy:      policy,
			Annotations: ToolAnnotations{ReadOnlyHint: policy.ReadOnly, DestructiveHint: !policy.ReadOnly, IdempotentHint: policy.RetrySafe, OpenWorldHint: policy.NetworkAccess},
		})
	}

	return s.successResponse(req.ID, ToolsListResult{Tools: tools, TTLMs: ToolsListTTLMS})
}

func (s *Server) handleToolsCall(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, "invalid tools/call params")
	}

	_, ok := s.GetTool(params.Name)
	if !ok {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, fmt.Sprintf("unknown tool: %s", params.Name))
	}

	result, err := s.ExecuteTool(ctx, params.Name, params.Arguments)
	if err != nil {
		return s.successResponse(req.ID, &ToolResult{
			Content: []ContentBlock{{Type: "text", Text: fmt.Sprintf("Error: %s", err.Error())}},
			IsError: true,
		})
	}

	return s.successResponse(req.ID, result)
}

func (s *Server) handleWorkflowRun(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	ctx, cancel := context.WithTimeout(ctx, s.workflowTimeout)
	defer cancel()
	if s.workflow == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "workflow engine not configured")
	}

	result, err := s.workflow.RunFromJSON(ctx, req.Params)
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}

	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  json.RawMessage(result),
	}
}

func (s *Server) handleReportGenerate(req *JSONRPCRequest) *JSONRPCResponse {
	if s.reporter == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "report generator not configured")
	}

	output, err := s.reporter.GenerateFromJSON(req.Params)
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}

	return s.successResponse(req.ID, &ToolResult{
		Content: []ContentBlock{{Type: "text", Text: output}},
	})
}

func (s *Server) handleCampaignRun(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	ctx, cancel := context.WithTimeout(ctx, s.workflowTimeout)
	defer cancel()
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}

	result, err := s.campaign.RunFromJSON(ctx, req.Params)
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}

	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  json.RawMessage(result),
	}
}

func (s *Server) handleCampaignQuery(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}

	var (
		result json.RawMessage
		err    error
	)
	switch req.Method {
	case MethodCampaignStatus:
		result, err = s.campaign.StatusFromJSON(req.Params)
	case MethodCampaignList:
		result, err = s.campaign.ListFromJSON(req.Params)
	case MethodCampaignCancel:
		result, err = s.campaign.CancelFromJSON(req.Params)
	case MethodCampaignTemplates:
		result, err = s.campaign.TemplatesFromJSON(req.Params)
	case MethodCampaignTemplateGet:
		result, err = s.campaign.GetTemplateFromJSON(req.Params)
	case MethodCampaignTemplateSave:
		result, err = s.campaign.SaveTemplateFromJSON(req.Params)
	default:
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
	}
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}

	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  json.RawMessage(result),
	}
}

func (s *Server) successResponse(id json.RawMessage, result any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
}

func (s *Server) errorResponse(id json.RawMessage, code int, message string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   &JSONRPCError{Code: code, Message: message},
	}
}

// unsupportedVersionData is the structured payload attached to
// ErrCodeUnsupportedProtocolVersion responses.
type unsupportedVersionData struct {
	Supported []string `json:"supported"`
	Requested string   `json:"requested"`
}

// unsupportedProtocolVersionError builds the -32022 error shared by the
// handler (body _meta) and the streamable HTTP transport (headers).
func unsupportedProtocolVersionError(id json.RawMessage, requested string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    ErrCodeUnsupportedProtocolVersion,
			Message: fmt.Sprintf("unsupported protocol version %q", requested),
			Data:    unsupportedVersionData{Supported: []string{ProtocolVersion}, Requested: requested},
		},
	}
}
