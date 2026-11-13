package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// tasksExtMeta is the params._meta payload a client sends to declare the
// tasks extension for one request.
const tasksExtMeta = `{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`

// requestWithMeta builds a JSON-RPC request whose params object carries the
// tasks-extension _meta declaration alongside the given params.
func requestWithMeta(t *testing.T, method string, params json.RawMessage) json.RawMessage {
	t.Helper()
	obj := map[string]json.RawMessage{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &obj); err != nil || obj == nil {
			t.Fatalf("params must be a JSON object: %s", params)
		}
	}
	obj["_meta"] = json.RawMessage(tasksExtMeta)
	merged, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("merge _meta: %v", err)
	}
	data, err := json.Marshal(JSONRPCRequest{
		JSONRPC: JSONRPCVersion,
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  merged,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

func TestCampaignStartDispatchAsync(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	body := requestWithMeta(t, MethodCampaignStart, json.RawMessage(`{"steps":[{"id":"a","tool":"nmap_port_scan"}]}`))
	resp := decodeResponse(t, srv.HandleRawContext(context.Background(), body))
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected success, got %+v", resp)
	}
	if !engine.startAsyncCalled {
		t.Fatal("tasks-capable campaign/start must take the async path")
	}
	if engine.runCalled {
		t.Fatal("tasks-capable campaign/start must not run synchronously")
	}
	assertResultContains(t, resp, `"resultType":"task"`)
	assertResultContains(t, resp, `"taskId":"wf_1"`)
	assertResultContains(t, resp, `"status":"working"`)
	assertResultContains(t, resp, `"ttlMs":86400000`)
	assertResultContains(t, resp, `"pollIntervalMs":2000`)
}

func TestCampaignStartDispatchSyncWithoutCapability(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	params := json.RawMessage(`{"steps":[{"id":"a","tool":"nmap_port_scan"}]}`)
	resp := decodeResponse(t, srv.HandleRawContext(context.Background(), request(t, MethodCampaignStart, params)))
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected success, got %+v", resp)
	}
	if !engine.runCalled {
		t.Fatal("capability-less campaign/start must behave exactly like campaign/run")
	}
	if engine.startAsyncCalled {
		t.Fatal("capability-less campaign/start must not take the async path")
	}
	assertResultContains(t, resp, `"workflow_id":"wf_1"`)
}

func TestTasksMethodsDispatch(t *testing.T) {
	srv, engine := newCampaignTestServer(t)
	ctx := context.Background()

	t.Run("get", func(t *testing.T) {
		resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, MethodTasksGet, json.RawMessage(`{"taskId":"wf_1"}`))))
		if resp == nil || resp.Error != nil {
			t.Fatalf("expected success, got %+v", resp)
		}
		if !engine.statusCalled {
			t.Fatal("tasks/get must read campaign state")
		}
		assertResultContains(t, resp, `"status":"working"`)
	})

	t.Run("cancel", func(t *testing.T) {
		engine.cancelCalled = false
		resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, MethodTasksCancel, json.RawMessage(`{"taskId":"wf_1"}`))))
		if resp == nil || resp.Error != nil {
			t.Fatalf("expected success, got %+v", resp)
		}
		if !engine.cancelCalled {
			t.Fatal("tasks/cancel must delegate to the engine's cancel")
		}
	})

	t.Run("update", func(t *testing.T) {
		resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, MethodTasksUpdate, json.RawMessage(`{"taskId":"wf_1","inputResponses":{"approval":{"approved":true}}}`))))
		if resp == nil || resp.Error != nil {
			t.Fatalf("expected success, got %+v", resp)
		}
		assertResultContains(t, resp, `"accepted":true`)
	})

	t.Run("get requires taskId", func(t *testing.T) {
		resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, MethodTasksGet, json.RawMessage(`{}`))))
		if resp == nil || resp.Error == nil || resp.Error.Code != ErrCodeInvalidParams {
			t.Fatalf("expected -32602, got %+v", resp)
		}
	})
}

func TestTasksMethodsNotConfigured(t *testing.T) {
	srv := NewServer("test", "1.0")
	ctx := context.Background()
	for _, method := range []string{MethodCampaignStart, MethodTasksGet, MethodTasksCancel, MethodTasksUpdate} {
		resp := decodeResponse(t, srv.HandleRawContext(ctx, request(t, method, json.RawMessage(`{}`))))
		if resp == nil || resp.Error == nil || resp.Error.Code != ErrCodeMethodNotFound {
			t.Fatalf("%s: expected method-not-found for unconfigured engine, got %+v", method, resp)
		}
	}
}
