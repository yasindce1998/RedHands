package mcp_test

// HTTP-transport-level test for the tasks extension: proves the per-request
// capability marker survives the streamable HTTP transport and that an
// async campaign keeps running after the HTTP request that started it has
// completed (its context is detached, not inherited).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/internal/app"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestStreamableHTTPTasksLifecycle(t *testing.T) {
	dir := t.TempDir()
	tool := newRecordingTool("safe_tool")

	srv := mcp.NewServer("test-server", "1.0.0")
	if err := srv.RegisterTool(tool); err != nil {
		t.Fatal(err)
	}
	srv.SetToolPolicy("safe_tool", mcp.ToolPolicy{})
	cfg := &config.Config{
		WorkflowStateDir:    filepath.Join(dir, "state"),
		WorkflowTemplateDir: filepath.Join(dir, "templates"),
		WorkflowMaxParallel: 4,
	}
	app.SetupCampaign(srv, cfg, nil, nil)

	server := httptest.NewServer(srv.StreamableHTTPHandler(context.Background(), mcp.DefaultHTTPPath, mcp.HTTPOptions{}))
	t.Cleanup(server.Close)

	post := func(t *testing.T, method string, params string) (int, map[string]json.RawMessage, *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}) {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
		req, err := http.NewRequest(http.MethodPost, server.URL+mcp.DefaultHTTPPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", mcp.ProtocolVersion)
		req.Header.Set("Mcp-Method", method)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var rpc struct {
			Result map[string]json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(data, &rpc); err != nil {
			t.Fatalf("response is not JSON-RPC: %s", data)
		}
		return resp.StatusCode, rpc.Result, rpc.Error
	}

	// campaign/start over HTTP with the tasks capability declared in the
	// body _meta: a CreateTaskResult must come back immediately.
	params := `{"id":"http-task","steps":[{"id":"a","tool":"safe_tool"}],"_meta":{"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}}`
	status, result, rpcErr := post(t, mcp.MethodCampaignStart, params)
	if status != http.StatusOK || rpcErr != nil {
		t.Fatalf("campaign/start over HTTP: status=%d err=%+v", status, rpcErr)
	}
	var created mcp.CreateTaskResult
	if err := json.Unmarshal(mustJSON(t, result), &created); err != nil {
		t.Fatal(err)
	}
	if created.ResultType != mcp.ResultTypeTask || created.Task.TaskID != "http-task" || created.Task.Status != mcp.TaskStatusWorking {
		t.Fatalf("CreateTaskResult = %+v", created.Task)
	}

	// The HTTP request that started the task is long gone; poll tasks/get
	// until the detached background run completes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, result, rpcErr := post(t, mcp.MethodTasksGet, `{"taskId":"http-task"}`)
		if status != http.StatusOK || rpcErr != nil {
			t.Fatalf("tasks/get: status=%d err=%+v", status, rpcErr)
		}
		var task struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(mustJSON(t, result), &task); err != nil {
			t.Fatal(err)
		}
		if task.Status == mcp.TaskStatusCompleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task stuck in %q over HTTP", task.Status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if runs := tool.runs(); runs != 1 {
		t.Fatalf("campaign executed %d times, want 1", runs)
	}

	// The completed task serves the persisted final result.
	_, result, rpcErr = post(t, mcp.MethodTasksGet, `{"taskId":"http-task"}`)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	var task struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(mustJSON(t, result), &task); err != nil || len(task.Result) == 0 {
		t.Fatalf("completed task over HTTP must carry a result: %v", result)
	}
}
