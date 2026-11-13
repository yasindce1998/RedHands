package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// fakeCampaignEngine is a minimal CampaignEngine used to exercise dispatch.
type fakeCampaignEngine struct {
	runCalled        bool
	startAsyncCalled bool
	statusCalled     bool
	listCalled       bool
	resumeCalled     bool
	cancelCalled     bool
	templatesCall    bool
	getCalled        bool
	saveCalled       bool
	failRun          error
	runResult        json.RawMessage
	receivedParams   json.RawMessage
}

func (f *fakeCampaignEngine) RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	f.runCalled = true
	f.receivedParams = params
	if f.failRun != nil {
		return nil, f.failRun
	}
	if f.runResult != nil {
		return f.runResult, nil
	}
	return json.RawMessage(`{"workflow_id":"wf_1","success":true}`), nil
}

func (f *fakeCampaignEngine) StatusFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.statusCalled = true
	return json.RawMessage(`{"workflow_id":"wf_1","status":"running"}`), nil
}

func (f *fakeCampaignEngine) ListFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.listCalled = true
	return json.RawMessage(`[]`), nil
}

func (f *fakeCampaignEngine) ResumeFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	f.resumeCalled = true
	return json.RawMessage(`{"workflow_id":"wf_1","success":true}`), nil
}

func (f *fakeCampaignEngine) CancelFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.cancelCalled = true
	return json.RawMessage(`{"cancelled":true}`), nil
}

func (f *fakeCampaignEngine) TemplatesFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.templatesCall = true
	return json.RawMessage(`[]`), nil
}

func (f *fakeCampaignEngine) GetTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.getCalled = true
	return json.RawMessage(`{"name":"x"}`), nil
}

func (f *fakeCampaignEngine) SaveTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	f.saveCalled = true
	return json.RawMessage(`{"saved":true}`), nil
}

func (f *fakeCampaignEngine) StartAsyncFromJSON(ctx context.Context, params json.RawMessage) (string, bool, error) {
	f.startAsyncCalled = true
	f.receivedParams = params
	if f.failRun != nil {
		return "", false, f.failRun
	}
	return "wf_1", false, nil
}

func (f *fakeCampaignEngine) TaskUpdateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(`{"accepted":true}`), nil
}

func newCampaignTestServer(t *testing.T) (*Server, *fakeCampaignEngine) {
	t.Helper()
	srv := NewServer("test", "1.0")
	engine := &fakeCampaignEngine{}
	srv.SetCampaignEngine(engine)
	return srv, engine
}

func TestCampaignRunDispatch(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	params := json.RawMessage(`{"steps":[{"id":"a","tool":"nmap_port_scan"}]}`)
	resp := decodeResponse(t, srv.HandleRawContext(context.Background(), request(t, MethodCampaignRun, params)))
	if resp == nil {
		t.Fatal("expected response")
	}
	if !engine.runCalled {
		t.Fatal("campaign engine RunFromJSON not called")
	}
	if string(engine.receivedParams) != string(params) {
		t.Fatalf("params not forwarded: %s", engine.receivedParams)
	}
	assertResultContains(t, resp, `"workflow_id":"wf_1"`)
}

func TestCampaignQueryMethodsDispatch(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	ctx := context.Background()

	for _, tc := range []struct {
		method   string
		params   json.RawMessage
		check    func(testing.TB)
		contains string
	}{
		{MethodCampaignStatus, json.RawMessage(`{"workflow_id":"wf_1"}`), func(tb testing.TB) { assert(tb, engine.statusCalled, "status") }, `"status":"running"`},
		{MethodCampaignList, json.RawMessage(`{}`), func(tb testing.TB) { assert(tb, engine.listCalled, "list") }, `[]`},
		{MethodCampaignResume, json.RawMessage(`{"workflow_id":"wf_1"}`), func(tb testing.TB) { assert(tb, engine.resumeCalled, "resume") }, `"success":true`},
		{MethodCampaignCancel, json.RawMessage(`{"workflow_id":"wf_1"}`), func(tb testing.TB) { assert(tb, engine.cancelCalled, "cancel") }, `"cancelled":true`},
		{MethodCampaignTemplates, json.RawMessage(`{}`), func(tb testing.TB) { assert(tb, engine.templatesCall, "templates") }, `[]`},
		{MethodCampaignTemplateGet, json.RawMessage(`{"name":"x"}`), func(tb testing.TB) { assert(tb, engine.getCalled, "template get") }, `"name":"x"`},
		{MethodCampaignTemplateSave, json.RawMessage(`{"name":"x","steps":[]}`), func(tb testing.TB) { assert(tb, engine.saveCalled, "template save") }, `"saved":true`},
	} {
		t.Run(tc.method, func(t *testing.T) {
			resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, tc.method, tc.params)))
			if resp == nil {
				t.Fatal("expected response")
			}
			tc.check(t)
			assertResultContains(t, resp, tc.contains)
		})
	}
}

func TestCampaignRunError(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	engine.failRun = fmt.Errorf("workflow has no steps")
	resp := decodeResponse(t, srv.HandleRawContext(context.Background(), request(t, MethodCampaignRun, json.RawMessage(`{}`))))
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %+v", resp)
	}
	if resp.Error.Code != ErrCodeInternal {
		t.Fatalf("expected internal error code, got %d", resp.Error.Code)
	}
}

func TestCampaignNotConfigured(t *testing.T) {
	srv := NewServer("test", "1.0")
	resp := decodeResponse(t, srv.HandleRawContext(context.Background(), request(t, MethodCampaignRun, json.RawMessage(`{}`))))
	if resp == nil || resp.Error == nil || resp.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method-not-found for unconfigured engine, got %+v", resp)
	}
	resp = decodeResponse(t, srv.HandleRawContext(context.Background(), request(t, MethodCampaignStatus, json.RawMessage(`{}`))))
	if resp == nil || resp.Error == nil || resp.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method-not-found for unconfigured engine, got %+v", resp)
	}
}

func request(t *testing.T, method string, params json.RawMessage) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

// decodeResponse parses a raw JSON-RPC response.
func decodeResponse(t *testing.T, raw json.RawMessage) *JSONRPCResponse {
	t.Helper()
	if raw == nil {
		t.Fatal("expected response")
	}
	var resp JSONRPCResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}
	return &resp
}

func assert(tb testing.TB, cond bool, what string) {
	tb.Helper()
	if !cond {
		tb.Fatalf("expected %s to be called", what)
	}
}

func assertResultContains(t *testing.T, resp *JSONRPCResponse, want string) {
	t.Helper()
	data, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if !contains(string(data), want) {
		t.Fatalf("result %s does not contain %s", data, want)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
