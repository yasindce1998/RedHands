package mcp

import "encoding/json"

const (
	JSONRPCVersion = "2.0"

	// ProtocolVersion is the modern MCP protocol revision this server speaks.
	ProtocolVersion = "2026-07-28"

	// Legacy protocol revisions still accepted for dual-era tolerance:
	// clients that open with the initialize handshake keep working.
	LegacyProtocolVersion2024 = "2024-11-05"
	LegacyProtocolVersion2025 = "2025-03-26"

	// JSONSchemaDialect202012 is the only JSON Schema dialect accepted in
	// tool input schemas that declare a $schema keyword.
	JSONSchemaDialect202012 = "https://json-schema.org/draft/2020-12/schema"

	// ToolsListTTLMS hints how long clients may cache the tools/list
	// catalog: the toolset is static for the lifetime of the process.
	ToolsListTTLMS = 300000

	MethodInitialize             = "initialize"
	MethodInitialized            = "notifications/initialized"
	MethodServerDiscover         = "server/discover"
	MethodToolsList              = "tools/list"
	MethodToolsCall              = "tools/call"
	MethodPing                   = "ping"
	MethodNotificationsCancelled = "notifications/cancelled"
	MethodWorkflowRun            = "workflow/run"
	MethodReportGenerate         = "report/generate"
	MethodCampaignRun            = "campaign/run"
	MethodCampaignStart          = "campaign/start"
	MethodCampaignStatus         = "campaign/status"
	MethodCampaignList           = "campaign/list"
	MethodCampaignResume         = "campaign/resume"
	MethodCampaignCancel         = "campaign/cancel"
	MethodCampaignTemplates      = "campaign/templates"
	MethodCampaignTemplateGet    = "campaign/template/get"
	MethodCampaignTemplateSave   = "campaign/template/save"

	// Tasks extension methods (io.modelcontextprotocol/tasks).
	MethodTasksGet    = "tasks/get"
	MethodTasksCancel = "tasks/cancel"
	MethodTasksUpdate = "tasks/update"

	// TasksExtension is the protocol extension name negotiated per-request
	// via _meta.clientCapabilities.extensions and advertised in
	// server/discover capabilities.extensions.
	TasksExtension = "io.modelcontextprotocol/tasks"

	// ErrCodeTaskFailed is attached to the error object of a tasks/get
	// result for a campaign that failed. It sits in the server-error range
	// (-32000), below the server's reserved custom codes.
	ErrCodeTaskFailed = -32000

	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
	ErrCodeUnauthorized   = -32001

	// ErrCodeHeaderMismatch is returned when transport-level headers
	// (Mcp-Method, Mcp-Name, MCP-Protocol-Version) are missing from or
	// inconsistent with the JSON-RPC body.
	ErrCodeHeaderMismatch = -32020
	// ErrCodeUnsupportedProtocolVersion is returned when a request
	// negotiates a protocol revision this server does not speak.
	ErrCodeUnsupportedProtocolVersion = -32022
)

// SupportedProtocolVersions lists every protocol revision the server
// accepts, newest first. The modern revision is negotiated per-request
// via _meta; the legacy ones via the initialize handshake.
func SupportedProtocolVersions() []string {
	return []string{ProtocolVersion, LegacyProtocolVersion2025, LegacyProtocolVersion2024}
}

// protocolVersionSupported reports whether v is a protocol revision this
// server accepts (modern plus dual-era legacy tolerance).
func protocolVersionSupported(v string) bool {
	return v == ProtocolVersion || v == LegacyProtocolVersion2025 || v == LegacyProtocolVersion2024
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type InitializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    ClientCaps `json:"capabilities"`
	ClientInfo      ClientInfo `json:"clientInfo"`
}

type ClientCaps struct {
	Roots    *RootsCap    `json:"roots,omitempty"`
	Sampling *SamplingCap `json:"sampling,omitempty"`
}

type RootsCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type SamplingCap struct{}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    ServerCaps `json:"capabilities"`
	ServerInfo      ServerInfo `json:"serverInfo"`
	// ProtocolVersions additionally advertises every revision the server
	// speaks. Additive field: legacy clients ignore it.
	ProtocolVersions []string `json:"protocolVersions,omitempty"`
}

type ServerCaps struct {
	Tools *ToolsCap `json:"tools,omitempty"`
}

type ToolsCap struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ToolsListResult struct {
	Tools []ToolDef `json:"tools"`
	// TTLMs hints how long the catalog may be cached (milliseconds).
	TTLMs int `json:"ttlMs,omitempty"`
}

type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Policy      ToolPolicy      `json:"x-redhands-policy"`
	Annotations ToolAnnotations `json:"annotations"`
}

type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint"`
	DestructiveHint bool `json:"destructiveHint"`
	IdempotentHint  bool `json:"idempotentHint"`
	OpenWorldHint   bool `json:"openWorldHint"`
}

type ToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// InputResponses carries the client's answers to a previous
	// input_required result for this same call (tasks extension / MRTR).
	// It is threaded into the execution context, not the tool arguments:
	// approval can never be granted by model-supplied tool arguments.
	InputResponses map[string]json.RawMessage `json:"inputResponses,omitempty"`
}

type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
	// StructuredContent carries a machine-readable result object alongside
	// the human-oriented content blocks (modern protocol revision).
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	// ResultType marks extended result shapes: "task" (a background task
	// was created) and "input_required" (the call paused waiting for the
	// client to answer inputRequests and re-issue the same call).
	ResultType string `json:"resultType,omitempty"`
	// InputRequests is populated when ResultType is "input_required". Each
	// entry names one request the client must answer; the answer comes
	// back as params.inputResponses with the same key.
	InputRequests map[string]InputRequest `json:"inputRequests,omitempty"`
}

// Extended resultType values.
const (
	// ResultTypeTask is the resultType of a CreateTaskResult.
	ResultTypeTask = "task"
	// ResultTypeInputRequired is the resultType of a result that paused
	// waiting for client input (MRTR approval gating).
	ResultTypeInputRequired = "input_required"
)

// InputRequestTypeElicitation is the only request type this server issues.
const InputRequestTypeElicitation = "elicitation/create"

// IsInputRequired reports whether a tool result paused waiting for client
// input (MRTR approval gating). The engine adapter uses it to translate an
// input_required result into an approval-required pause.
func IsInputRequired(r *ToolResult) bool {
	return r != nil && r.ResultType == ResultTypeInputRequired
}

// InputRequest describes one piece of input a client must provide before
// the paused call can proceed.
type InputRequest struct {
	// Type names the mechanism the client should use; this server only
	// issues "elicitation/create".
	Type string `json:"type"`
	// Message is the human-readable prompt to surface to the operator.
	Message string `json:"message"`
	// RequestID uniquely identifies this request; responses may echo it so
	// stale answers can be detected.
	RequestID string `json:"requestId"`
}

// CreateTaskResult is returned by campaign/start (and the campaign_start
// tool) when the request declared the tasks extension: the campaign runs
// in the background and the client polls tasks/get.
type CreateTaskResult struct {
	ResultType string  `json:"resultType"`
	Task       TaskRef `json:"task"`
}

// TaskRef identifies a background task.
type TaskRef struct {
	TaskID         string `json:"taskId"`
	Status         string `json:"status"`
	TTLMs          int    `json:"ttlMs"`
	PollIntervalMs int    `json:"pollIntervalMs"`
}

// Task lifecycle constants (io.modelcontextprotocol/tasks).
const (
	TaskStatusWorking       = "working"
	TaskStatusCompleted     = "completed"
	TaskStatusFailed        = "failed"
	TaskStatusCancelled     = "cancelled"
	TaskStatusInputRequired = "input_required"

	// TaskTTLMS is how long a finished task's state remains retrievable.
	TaskTTLMS = 86400000
	// TaskPollIntervalMS is the suggested polling interval for tasks/get.
	TaskPollIntervalMS = 2000
)

// GetTaskResult is the tasks/get result: the current state of a task.
type GetTaskResult struct {
	Status        string                  `json:"status"`
	StatusMessage string                  `json:"statusMessage,omitempty"`
	Result        json.RawMessage         `json:"result,omitempty"`
	Error         *JSONRPCError           `json:"error,omitempty"`
	InputRequests map[string]InputRequest `json:"inputRequests,omitempty"`
}

// TasksGetParams, TasksCancelParams and TasksUpdateParams are the params
// of the tasks/* methods.
type TasksGetParams struct {
	TaskID string `json:"taskId"`
}

type TasksCancelParams struct {
	TaskID string `json:"taskId"`
}

type TasksUpdateParams struct {
	TaskID         string                     `json:"taskId"`
	InputResponses map[string]json.RawMessage `json:"inputResponses"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// RequestMeta is the per-request metadata carried in a request's
// params._meta under namespaced keys. The body _meta is the source of
// truth for version negotiation; transport headers must agree with it.
type RequestMeta struct {
	// ProtocolVersion is the protocol revision the client wants to use for
	// this request, carried under io.modelcontextprotocol/protocolVersion.
	ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	// ClientInfo identifies the sending client for this request, carried
	// under io.modelcontextprotocol/clientInfo.
	ClientInfo *ClientInfo `json:"io.modelcontextprotocol/clientInfo,omitempty"`
	// ClientCapabilities declares per-request client capabilities under
	// io.modelcontextprotocol/clientCapabilities.
	ClientCapabilities *MetaClientCapabilities `json:"io.modelcontextprotocol/clientCapabilities,omitempty"`
}

// MetaClientCapabilities is the modern clientCapabilities object that may
// appear in request _meta. Unlike the legacy initialize capability block
// it carries an extensions map for protocol extensions the client knows.
type MetaClientCapabilities struct {
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// ParseRequestMeta extracts _meta from raw request params. The second
// return value reports whether params carried a _meta object at all; a
// request without _meta is treated as legacy-era (no validation).
func ParseRequestMeta(params json.RawMessage) (RequestMeta, bool) {
	var meta RequestMeta
	if len(params) == 0 {
		return meta, false
	}
	var wrapper struct {
		Meta *json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &wrapper); err != nil || wrapper.Meta == nil {
		return meta, false
	}
	if err := json.Unmarshal(*wrapper.Meta, &meta); err != nil {
		// _meta present but not an object: treat as absent (legacy tolerance).
		return meta, false
	}
	return meta, true
}

// DiscoverResult is the response to server/discover, the stateless modern
// replacement for the initialize handshake.
type DiscoverResult struct {
	ProtocolVersion  string       `json:"protocolVersion"`
	ServerInfo       ServerInfo   `json:"serverInfo"`
	ProtocolVersions []string     `json:"protocolVersions"`
	Capabilities     DiscoverCaps `json:"capabilities"`
}

// DiscoverCaps advertises server capabilities in server/discover results.
// Tools is always advertised; Extensions lists negotiated protocol
// extensions and is omitted when none exist.
type DiscoverCaps struct {
	Tools      *ToolsCap                  `json:"tools,omitempty"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}
