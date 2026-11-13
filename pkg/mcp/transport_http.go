package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DefaultHTTPPath is the default MCP endpoint for the streamable HTTP
// transport ("2026-07-28" protocol revision).
const DefaultHTTPPath = "/mcp"

// ServeStreamableHTTP serves the modern single-endpoint MCP transport on
// addr using the default endpoint path /mcp.
func (s *Server) ServeStreamableHTTP(ctx context.Context, addr string, opts HTTPOptions) error {
	return s.ServeStreamableHTTPWithPath(ctx, addr, DefaultHTTPPath, opts)
}

// ServeStreamableHTTPWithPath serves the modern single-endpoint MCP
// transport on addr with a custom endpoint path.
func (s *Server) ServeStreamableHTTPWithPath(ctx context.Context, addr, path string, opts HTTPOptions) error {
	return serveHTTP(ctx, addr, s.StreamableHTTPHandler(ctx, path, opts), opts)
}

// StreamableHTTPHandler implements the modern MCP streamable HTTP
// transport: a single endpoint, POST only, one JSON-RPC object per
// request/response, no sessions. It reuses the shared HTTP plumbing
// (TLS, timeouts, Origin checks, request auth, MaxRequestBytes) from
// http.go.
//
// Protocol rules implemented here:
//
//   - GET or DELETE on the endpoint answers 405 Method Not Allowed. This
//     is also the answer to legacy-client probes that expect the older
//     SSE-style transport on the same URL.
//   - Mcp-Session-Id and Last-Event-ID request headers are ignored
//     silently: the transport is stateless and carries no resumable
//     streams in v1.
//   - Every POST must carry MCP-Protocol-Version and Mcp-Method headers;
//     tools/call (and resources/read / prompts/get, should they ever be
//     served) additionally require Mcp-Name. Missing headers answer
//     HTTP 400 with JSON-RPC error -32020.
//   - Headers must agree with the JSON-RPC body: Mcp-Method with the
//     body method, Mcp-Name with params.name, and MCP-Protocol-Version
//     with the body's _meta protocolVersion when the body carries one.
//     Mismatches answer HTTP 400 with -32020. Header values encoded in
//     the Base64 sentinel form "=?base64?...?=" are decoded before
//     comparison. Mcp-Param-* headers are treated as opaque and are not
//     compared against body params in v1.
//   - An unsupported protocol version in the headers or the body _meta
//     answers HTTP 400 with -32022 and data.supported.
//   - An unknown RPC method answers HTTP 404 with a JSON-RPC -32601
//     body; modern clients use this status distinction to detect
//     modern servers.
//   - A JSON-RPC notification (no id) answers HTTP 202 with an empty
//     body. A request answers HTTP 200 with Content-Type
//     application/json and a single JSON object. The client's Accept
//     header may list application/json and/or text/event-stream; either
//     is accepted and the answer is always JSON in v1.
//   - Request execution runs on r.Context(), so a client aborting the
//     response stream cancels the in-flight work.
//
// Note for deployers: the TCP transport (transport_tcp.go) also
// qualifies as a spec-compliant custom transport — the spec permits
// custom transports with their own framing, and TCP's length-prefixed
// JSON-RPC frames (plus its mTLS authentication) satisfy those rules.
func (s *Server) StreamableHTTPHandler(ctx context.Context, path string, opts HTTPOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		s.serveStreamableHTTP(w, r, opts)
	})
	return mux
}

func (s *Server) serveStreamableHTTP(w http.ResponseWriter, r *http.Request, opts HTTPOptions) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed: the MCP endpoint accepts POST only", http.StatusMethodNotAllowed)
		return
	}
	// Mcp-Session-Id and Last-Event-ID are deliberately not read.

	reqCtx, ok := checkHTTPRequest(w, r, opts)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.errorResponse(nil, ErrCodeParse, "parse error"))
		return
	}
	if req.JSONRPC != JSONRPCVersion || req.Method == "" {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.errorResponse(req.ID, ErrCodeInvalidRequest, "invalid JSON-RPC request"))
		return
	}

	headerVersion := r.Header.Get("MCP-Protocol-Version")
	headerMethod := r.Header.Get("Mcp-Method")
	rawName := r.Header.Get("Mcp-Name")

	if headerVersion == "" {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, "missing MCP-Protocol-Version header"))
		return
	}
	if headerMethod == "" {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, "missing Mcp-Method header"))
		return
	}
	if methodRequiresMcpName(req.Method) && rawName == "" {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, fmt.Sprintf("missing Mcp-Name header for %s", req.Method)))
		return
	}
	if !protocolVersionSupported(headerVersion) {
		writeHTTPJSONRPC(w, http.StatusBadRequest, unsupportedProtocolVersionError(req.ID, headerVersion))
		return
	}
	// Body _meta is the source of truth: an unsupported version there is
	// reported as -32022 (handleRequest validates it too for non-HTTP
	// transports; the status mapping below would also yield 400).
	meta, _ := ParseRequestMeta(req.Params)
	if meta.ProtocolVersion != "" && !protocolVersionSupported(meta.ProtocolVersion) {
		writeHTTPJSONRPC(w, http.StatusBadRequest, unsupportedProtocolVersionError(req.ID, meta.ProtocolVersion))
		return
	}
	if headerMethod != req.Method {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, fmt.Sprintf("Mcp-Method header %q does not match body method %q", headerMethod, req.Method)))
		return
	}
	if methodRequiresMcpName(req.Method) {
		var params struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params, &params)
		if decoded := decodeHeaderSentinel(rawName); decoded != params.Name {
			writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, fmt.Sprintf("Mcp-Name header %q does not match params.name %q", rawName, params.Name)))
			return
		}
	}
	// When present, the body _meta version must agree with the header.
	if meta.ProtocolVersion != "" && headerVersion != meta.ProtocolVersion {
		writeHTTPJSONRPC(w, http.StatusBadRequest, s.headerMismatch(req.ID, fmt.Sprintf("MCP-Protocol-Version header %q does not match body _meta protocolVersion %q", headerVersion, meta.ProtocolVersion)))
		return
	}

	resp := s.handleRequest(reqCtx, &req)
	if resp == nil {
		// JSON-RPC notification: accepted, nothing to say.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if resp.Error != nil {
		switch resp.Error.Code {
		case ErrCodeMethodNotFound:
			// Modern clients detect modern servers via this status.
			writeHTTPJSONRPC(w, http.StatusNotFound, resp)
		case ErrCodeUnsupportedProtocolVersion:
			writeHTTPJSONRPC(w, http.StatusBadRequest, resp)
		default:
			writeHTTPJSONRPC(w, http.StatusOK, resp)
		}
		return
	}
	writeHTTPJSONRPC(w, http.StatusOK, resp)
}

func (s *Server) headerMismatch(id json.RawMessage, detail string) *JSONRPCResponse {
	return s.errorResponse(id, ErrCodeHeaderMismatch, "Header mismatch: "+detail)
}

// methodRequiresMcpName reports whether a request for the given RPC
// method must carry the Mcp-Name header.
func methodRequiresMcpName(method string) bool {
	switch method {
	case MethodToolsCall, "resources/read", "prompts/get":
		return true
	}
	return false
}

// decodeHeaderSentinel decodes the Base64 sentinel form "=?base64?...?="
// used for header values that need to survive transports that mangle
// non-ASCII or header-hostile characters. Values not in sentinel form
// are returned unchanged. An optional encoding token (e.g. "B") between
// the charset and payload, as in "=?base64?B?<data>?=", is tolerated.
// Undecodable sentinel values are returned as-is so the subsequent
// comparison fails loudly rather than silently.
func decodeHeaderSentinel(v string) string {
	rest, ok := strings.CutPrefix(v, "=?base64?")
	if !ok {
		return v
	}
	rest, ok = strings.CutSuffix(rest, "?=")
	if !ok {
		return v
	}
	if _, after, found := strings.Cut(rest, "?"); found {
		rest = after
	}
	if decoded, err := base64.StdEncoding.DecodeString(rest); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.URLEncoding.DecodeString(rest); err == nil {
		return string(decoded)
	}
	return v
}

// writeHTTPJSONRPC emits a single JSON-RPC object with an HTTP status.
func writeHTTPJSONRPC(w http.ResponseWriter, status int, resp *JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
