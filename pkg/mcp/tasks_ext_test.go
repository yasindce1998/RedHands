package mcp_test

// Full-stack tests for the io.modelcontextprotocol/tasks extension and
// MRTR approval gating: a real MCP server wired to the real campaign
// engine (via the app layer's executor adapter) and the real approval
// middleware. This is an external test package so it may import packages
// that themselves import pkg/mcp.

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/internal/app"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/execution"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// recordingTool is an MCP tool that records invocations and can block
// until released (to keep campaigns in "running" for cancel tests).
type recordingTool struct {
	name   string
	mu     sync.Mutex
	ran    int
	block  chan struct{}
	text   string
	fail   bool
	onExec func()
}

func newRecordingTool(name string) *recordingTool {
	return &recordingTool{name: name, text: "output of " + name}
}

func (t *recordingTool) Name() string        { return t.name }
func (t *recordingTool) Description() string { return "test tool " + t.name }
func (t *recordingTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object"}`)
}

func (t *recordingTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	t.mu.Lock()
	t.ran++
	t.mu.Unlock()
	if t.onExec != nil {
		t.onExec()
	}
	if t.block != nil {
		select {
		case <-t.block:
		case <-ctx.Done():
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: "interrupted"}},
				IsError: true,
			}, nil
		}
	}
	if t.fail {
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: "tool failed"}},
			IsError: true,
		}, nil
	}
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: t.text}},
	}, nil
}

func (t *recordingTool) runs() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ran
}

// taskTestServer wires a server with two tools — safe_tool (no approval
// required) and dangerous_tool (approval-gated, not in the approved list)
// — the real approval middleware, and the real campaign engine through the
// app layer's executor adapter.
type taskTestServer struct {
	srv       *mcp.Server
	safe      *recordingTool
	dangerous *recordingTool
	engine    *workflow.EnhancedEngine
}

func newTaskTestServer(t *testing.T) *taskTestServer {
	t.Helper()
	dir := t.TempDir()
	safe := newRecordingTool("safe_tool")
	dangerous := newRecordingTool("dangerous_tool")

	srv := mcp.NewServer("test", "1.0")
	if err := srv.RegisterTool(safe); err != nil {
		t.Fatal(err)
	}
	if err := srv.RegisterTool(dangerous); err != nil {
		t.Fatal(err)
	}
	// safe_tool needs no operator approval; dangerous_tool keeps the
	// conservative default (RequiresApproval) and is NOT approved.
	srv.SetToolPolicy("safe_tool", mcp.ToolPolicy{})
	srv.Use(execution.Approval(nil))

	cfg := &config.Config{
		WorkflowStateDir:    filepath.Join(dir, "state"),
		WorkflowTemplateDir: filepath.Join(dir, "templates"),
		WorkflowMaxParallel: 4,
	}
	engine := app.SetupCampaign(srv, cfg, nil, nil)
	return &taskTestServer{srv: srv, safe: safe, dangerous: dangerous, engine: engine}
}

// call sends one JSON-RPC request and decodes the response.
func (s *taskTestServer) call(t *testing.T, method string, params json.RawMessage) *mcp.JSONRPCResponse {
	t.Helper()
	body, err := json.Marshal(mcp.JSONRPCRequest{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := s.srv.HandleRawContext(context.Background(), body)
	if raw == nil {
		t.Fatal("expected a response")
	}
	var resp mcp.JSONRPCResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}
	return &resp
}

// callWithTasks is call with the tasks-extension _meta declaration merged
// into the params object.
func (s *taskTestServer) callWithTasks(t *testing.T, method string, params json.RawMessage) *mcp.JSONRPCResponse {
	t.Helper()
	obj := map[string]json.RawMessage{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &obj); err != nil {
			t.Fatalf("params must be an object: %s", params)
		}
	}
	obj["_meta"] = json.RawMessage(`{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`)
	merged, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return s.call(t, method, merged)
}

func resultJSON(t *testing.T, resp *mcp.JSONRPCResponse) map[string]json.RawMessage {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected error response: %+v", resp.Error)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(mustJSON(t, resp.Result), &obj); err != nil {
		t.Fatalf("result not an object: %v", err)
	}
	return obj
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func jsonFieldString(t *testing.T, obj map[string]json.RawMessage, field string) string {
	t.Helper()
	raw, ok := obj[field]
	if !ok {
		t.Fatalf("result missing %q: %v", field, obj)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("field %q not a string: %s", field, raw)
	}
	return s
}

// pollTaskStatus polls tasks/get until the task reaches want.
func (s *taskTestServer) pollTaskStatus(t *testing.T, taskID, want string) map[string]json.RawMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := s.call(t, mcp.MethodTasksGet, json.RawMessage(`{"taskId":"`+taskID+`"}`))
		if resp.Error != nil {
			t.Fatalf("tasks/get %s: %+v", taskID, resp.Error)
		}
		obj := resultJSON(t, resp)
		if jsonFieldString(t, obj, "status") == want {
			return obj
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s stuck, want %q: %v", taskID, want, obj)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTasksLifecycleStartPollComplete(t *testing.T) {
	ts := newTaskTestServer(t)

	resp := ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"life-1","steps":[{"id":"a","tool":"safe_tool"},{"id":"b","tool":"safe_tool"}]}`))
	result := resultJSON(t, resp)
	if jsonFieldString(t, result, "resultType") != "task" {
		t.Fatalf("resultType = %v", result)
	}
	var created mcp.CreateTaskResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &created); err != nil {
		t.Fatal(err)
	}
	if created.Task.TaskID != "life-1" || created.Task.Status != mcp.TaskStatusWorking ||
		created.Task.TTLMs != mcp.TaskTTLMS || created.Task.PollIntervalMs != mcp.TaskPollIntervalMS {
		t.Fatalf("CreateTaskResult = %+v", created.Task)
	}

	final := ts.pollTaskStatus(t, "life-1", mcp.TaskStatusCompleted)
	var taskResult struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(mustJSON(t, final), &taskResult); err != nil || len(taskResult.Result) == 0 {
		t.Fatalf("completed task must carry a result: %v", final)
	}

	// The completed task's result equals the synchronous campaign/run
	// output for the same playbook (modulo the workflow id).
	syncResp := ts.call(t, mcp.MethodCampaignRun, json.RawMessage(
		`{"id":"life-sync","steps":[{"id":"a","tool":"safe_tool"},{"id":"b","tool":"safe_tool"}]}`))
	syncBytes := mustJSON(t, syncResp.Result)
	var compact bytes.Buffer
	if err := json.Compact(&compact, taskResult.Result); err != nil {
		t.Fatal(err)
	}
	async := bytes.Replace(compact.Bytes(), []byte(`"life-1"`), []byte(`"life-sync"`), 1)
	if !bytes.Equal(async, syncBytes) {
		t.Fatalf("async result != sync campaign/run output:\n async: %s\n sync:  %s", async, syncBytes)
	}
}

func TestTasksLifecycleWorkingBeforeCompletion(t *testing.T) {
	ts := newTaskTestServer(t)
	release := make(chan struct{})
	ts.safe.mu.Lock()
	ts.safe.block = release
	ts.safe.mu.Unlock()

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"life-blocked","steps":[{"id":"a","tool":"safe_tool"}]}`))
	obj := ts.pollTaskStatus(t, "life-blocked", mcp.TaskStatusWorking)
	if jsonFieldString(t, obj, "status") != mcp.TaskStatusWorking {
		t.Fatalf("status = %v", obj)
	}
	close(release)
	ts.pollTaskStatus(t, "life-blocked", mcp.TaskStatusCompleted)
}

func TestTasksCancelMidRun(t *testing.T) {
	ts := newTaskTestServer(t)
	ts.safe.mu.Lock()
	ts.safe.block = make(chan struct{})
	ts.safe.mu.Unlock()

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"life-cancel","steps":[{"id":"a","tool":"safe_tool"}]}`))
	ts.pollTaskStatus(t, "life-cancel", mcp.TaskStatusWorking)

	ack := ts.call(t, mcp.MethodTasksCancel, json.RawMessage(`{"taskId":"life-cancel"}`))
	if ack.Error != nil {
		t.Fatalf("tasks/cancel: %+v", ack.Error)
	}

	ts.pollTaskStatus(t, "life-cancel", mcp.TaskStatusCancelled)
}

func TestCampaignStartIdempotentWhileRunning(t *testing.T) {
	ts := newTaskTestServer(t)
	ts.safe.mu.Lock()
	ts.safe.block = make(chan struct{})
	ts.safe.mu.Unlock()

	first := ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"life-idem","steps":[{"id":"a","tool":"safe_tool"}]}`))
	second := ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"life-idem","steps":[{"id":"a","tool":"safe_tool"}]}`))
	for _, resp := range []*mcp.JSONRPCResponse{first, second} {
		result := resultJSON(t, resp)
		if jsonFieldString(t, result, "resultType") != "task" {
			t.Fatalf("duplicate start must answer with the task form: %v", result)
		}
		var created mcp.CreateTaskResult
		if err := json.Unmarshal(mustJSON(t, resp.Result), &created); err != nil {
			t.Fatal(err)
		}
		if created.Task.TaskID != "life-idem" || created.Task.Status != mcp.TaskStatusWorking {
			t.Fatalf("duplicate start must address the live task: %+v", created.Task)
		}
	}

	// Unblock and let the single campaign finish.
	ts.safe.mu.Lock()
	close(ts.safe.block)
	ts.safe.mu.Unlock()
	ts.pollTaskStatus(t, "life-idem", mcp.TaskStatusCompleted)
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("idempotent start executed the campaign %d times, want 1", runs)
	}
}

func TestTasksGetUnknownTask(t *testing.T) {
	ts := newTaskTestServer(t)
	resp := ts.call(t, mcp.MethodTasksGet, json.RawMessage(`{"taskId":"missing"}`))
	if resp.Error == nil || resp.Error.Code != mcp.ErrCodeInvalidParams {
		t.Fatalf("expected -32602 for unknown taskId, got %+v", resp)
	}
}

func TestTasksCancelUnknownTask(t *testing.T) {
	ts := newTaskTestServer(t)
	resp := ts.call(t, mcp.MethodTasksCancel, json.RawMessage(`{"taskId":"missing"}`))
	if resp.Error == nil || resp.Error.Code != mcp.ErrCodeInvalidParams {
		t.Fatalf("expected -32602 for unknown taskId, got %+v", resp)
	}
}

func TestTasksUpdateUnknownKeyAndTask(t *testing.T) {
	ts := newTaskTestServer(t)
	// Unknown task id: invalid params.
	resp := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"missing","inputResponses":{"approval":{"approved":true}}}`))
	if resp.Error == nil || resp.Error.Code != mcp.ErrCodeInvalidParams {
		t.Fatalf("expected -32602 for unknown taskId, got %+v", resp)
	}
	// Unknown key on a live task: ack and ignore.
	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"upd-1","steps":[{"id":"a","tool":"safe_tool"}]}`))
	resp = ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"upd-1","inputResponses":{"unrelated":{"x":1}}}`))
	if resp.Error != nil {
		t.Fatalf("unknown key must be acknowledged: %+v", resp.Error)
	}
	obj := resultJSON(t, resp)
	var accepted bool
	if err := json.Unmarshal(obj["accepted"], &accepted); err != nil || !accepted {
		t.Fatalf("ack = %v", obj)
	}
	ts.pollTaskStatus(t, "upd-1", mcp.TaskStatusCompleted)
}

// TestCampaignStartWithoutCapabilityIsSync: with no tasks-extension
// declaration, campaign/start is exactly campaign/run.
func TestCampaignStartWithoutCapabilityIsSync(t *testing.T) {
	ts := newTaskTestServer(t)
	resp := ts.call(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"sync-1","steps":[{"id":"a","tool":"safe_tool"}]}`))
	result := resultJSON(t, resp)
	if _, isTask := result["resultType"]; isTask {
		t.Fatalf("capability-less campaign/start must not return a task form: %v", result)
	}
	if jsonFieldString(t, result, "workflow_id") != "sync-1" {
		t.Fatalf("sync result = %v", result)
	}
	if jsonFieldString(t, result, "status") != "completed" {
		t.Fatalf("campaign must have run to completion synchronously: %v", result)
	}
}

// TestMRTRToolsCallApprovalFlow covers the synchronous MRTR path:
// gated call without capability fails closed; with the tasks capability it
// returns input_required; re-issuing with an affirmative response executes
// the tool once; a non-affirmative response is a denial.
func TestMRTRToolsCallApprovalFlow(t *testing.T) {
	ts := newTaskTestServer(t)

	// Without the capability: current fail-closed behavior.
	resp := ts.call(t, mcp.MethodToolsCall, json.RawMessage(`{"name":"dangerous_tool","arguments":{}}`))
	var denied mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &denied); err != nil {
		t.Fatal(err)
	}
	if !denied.IsError || !bytes.Contains([]byte(denied.Content[0].Text), []byte("requires operator approval")) {
		t.Fatalf("capability-less call must fail closed: %+v", denied)
	}

	// With the capability: input_required with an approval inputRequest.
	resp = ts.callWithTasks(t, mcp.MethodToolsCall, json.RawMessage(`{"name":"dangerous_tool","arguments":{}}`))
	var required mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &required); err != nil {
		t.Fatal(err)
	}
	if required.IsError {
		t.Fatalf("input_required is not an error: %+v", required)
	}
	if required.ResultType != mcp.ResultTypeInputRequired {
		t.Fatalf("resultType = %q, want input_required", required.ResultType)
	}
	req, ok := required.InputRequests[mcp.ApprovalInputKey]
	if !ok || req.Type != mcp.InputRequestTypeElicitation || req.RequestID == "" || req.Message == "" {
		t.Fatalf("inputRequests = %+v", required.InputRequests)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatalf("gated tool must not execute before approval, ran %d times", runs)
	}

	// A non-affirmative response is an explicit denial.
	resp = ts.callWithTasks(t, mcp.MethodToolsCall, json.RawMessage(
		`{"name":"dangerous_tool","arguments":{},"inputResponses":{"approval":{"approved":false}}}`))
	var deniedExplicit mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &deniedExplicit); err != nil {
		t.Fatal(err)
	}
	if !deniedExplicit.IsError || !bytes.Contains([]byte(deniedExplicit.Content[0].Text), []byte("denied")) {
		t.Fatalf("explicit denial must fail: %+v", deniedExplicit)
	}

	// Approval in the tool ARGUMENTS is never honored (fail closed).
	resp = ts.callWithTasks(t, mcp.MethodToolsCall, json.RawMessage(
		`{"name":"dangerous_tool","arguments":{"approved":true}}`))
	var argApproval mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &argApproval); err != nil {
		t.Fatal(err)
	}
	if argApproval.ResultType != mcp.ResultTypeInputRequired || ts.dangerous.runs() != 0 {
		t.Fatalf("approval must never come from tool arguments: %+v", argApproval)
	}

	// Re-issue with an affirmative inputResponses: executes, once.
	resp = ts.callWithTasks(t, mcp.MethodToolsCall, json.RawMessage(
		`{"name":"dangerous_tool","arguments":{},"inputResponses":{"approval":{"approved":true,"requestId":"`+req.RequestID+`"}}}`))
	var approved mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.IsError || approved.ResultType != "" {
		t.Fatalf("approved call must execute normally: %+v", approved)
	}
	if runs := ts.dangerous.runs(); runs != 1 {
		t.Fatalf("approved call must execute exactly once, ran %d times", runs)
	}

	// The bypass is per-call: the next call without a response trips again.
	resp = ts.callWithTasks(t, mcp.MethodToolsCall, json.RawMessage(`{"name":"dangerous_tool","arguments":{}}`))
	var again mcp.ToolResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &again); err != nil {
		t.Fatal(err)
	}
	if again.ResultType != mcp.ResultTypeInputRequired {
		t.Fatalf("bypass must not persist across calls: %+v", again)
	}
}

// TestMRTRCampaignApprovalFlow covers the asynchronous MRTR path: a
// campaign step that trips approval pauses the task as input_required;
// tasks/update approves; campaign/resume completes the run with the gated
// step executed through the one-call bypass.
func TestMRTRCampaignApprovalFlow(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"mrtr-1","steps":[{"id":"gate","tool":"dangerous_tool"},{"id":"after","tool":"safe_tool"}]}`))

	obj := ts.pollTaskStatus(t, "mrtr-1", mcp.TaskStatusInputRequired)
	if _, ok := obj["inputRequests"]; !ok {
		t.Fatalf("input_required task must carry inputRequests: %v", obj)
	}
	var taskResult struct {
		InputRequests map[string]mcp.InputRequest `json:"inputRequests"`
	}
	if err := json.Unmarshal(mustJSON(t, obj), &taskResult); err != nil {
		t.Fatal(err)
	}
	inputReq, ok := taskResult.InputRequests[mcp.ApprovalInputKey]
	if !ok || inputReq.Type != mcp.InputRequestTypeElicitation || inputReq.RequestID == "" {
		t.Fatalf("approval inputRequest = %+v", taskResult.InputRequests)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatalf("gated step must not execute before approval, ran %d times", runs)
	}

	// Approve via tasks/update, then resume.
	ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"mrtr-1","inputResponses":{"approval":{"approved":true,"requestId":"`+inputReq.RequestID+`"}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}

	resume := ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"mrtr-1"}`))
	if resume.Error != nil {
		t.Fatalf("campaign/resume: %+v", resume.Error)
	}
	var resumed workflow.WorkflowResult
	if err := json.Unmarshal(mustJSON(t, resume.Result), &resumed); err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" || !resumed.Success {
		t.Fatalf("resumed campaign = %+v", resumed)
	}
	if runs := ts.dangerous.runs(); runs != 1 {
		t.Fatalf("approved step must execute exactly once, ran %d times", runs)
	}
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("step after the gate must run once, ran %d times", runs)
	}
}

// TestMRTRCampaignApprovalDenied: a denied response fails the gated step
// and (with the default on_fail policy) the campaign.
func TestMRTRCampaignApprovalDenied(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"mrtr-deny","steps":[{"id":"gate","tool":"dangerous_tool"},{"id":"after","tool":"safe_tool"}]}`))
	ts.pollTaskStatus(t, "mrtr-deny", mcp.TaskStatusInputRequired)

	ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"mrtr-deny","inputResponses":{"approval":{"approved":false}}}`))
	ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"mrtr-deny"}`))

	obj := ts.pollTaskStatus(t, "mrtr-deny", mcp.TaskStatusFailed)
	var taskResult struct {
		Error *mcp.JSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(mustJSON(t, obj), &taskResult); err != nil {
		t.Fatal(err)
	}
	if taskResult.Error == nil || taskResult.Error.Code != mcp.ErrCodeTaskFailed {
		t.Fatalf("failed task error = %+v", taskResult.Error)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatal("denied step must never execute")
	}
	if runs := ts.safe.runs(); runs != 0 {
		t.Fatal("steps after a denied on_fail:stop step must not run")
	}
}

// TestCampaignRunSyncApprovalFailsClosed: without the tasks capability a
// campaign step that trips approval keeps today's behavior (step failure).
func TestCampaignRunSyncApprovalFailsClosed(t *testing.T) {
	ts := newTaskTestServer(t)
	resp := ts.call(t, mcp.MethodCampaignRun, json.RawMessage(
		`{"id":"sync-gate","steps":[{"id":"gate","tool":"dangerous_tool"}]}`))
	if resp.Error != nil {
		t.Fatalf("campaign/run: %+v", resp.Error)
	}
	var result workflow.WorkflowResult
	if err := json.Unmarshal(mustJSON(t, resp.Result), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" {
		t.Fatalf("sync campaign over a gated tool = %+v, want failed", result)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatal("gated tool must not execute without capability")
	}
}
