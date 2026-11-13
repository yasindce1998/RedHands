package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type deadlineWorkflow struct{}

func (deadlineWorkflow) RunFromJSON(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWorkflowDeadline(t *testing.T) {
	srv := NewServer("test", "1")
	srv.SetWorkflowRunner(deadlineWorkflow{})
	srv.SetWorkflowTimeout(10 * time.Millisecond)
	start := time.Now()
	r := srv.HandleRaw(json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"workflow/run","params":{}}`))
	if time.Since(start) > time.Second || len(r) == 0 {
		t.Fatal("workflow deadline not enforced")
	}
}

func TestNotificationsHaveNoResponse(t *testing.T) {
	srv := NewServer("test", "1")
	if err := srv.RegisterTool(&mockTool{}); err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{`{"jsonrpc":"2.0","method":"ping"}`, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`, `{"jsonrpc":"2.0","method":"unknown"}`} {
		if response := srv.HandleRaw(json.RawMessage(message)); response != nil {
			t.Fatalf("notification produced response: %s", response)
		}
	}
}

func TestToolArgumentsMustBeObjects(t *testing.T) {
	srv := NewServer("test", "1")
	if err := srv.RegisterTool(&mockTool{}); err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{`null`, `[]`, `"text"`, `{invalid`} {
		if _, err := srv.ExecuteTool(context.Background(), "test_tool", json.RawMessage(args)); err == nil {
			t.Fatalf("accepted %s", args)
		}
	}
}

func FuzzHandleRaw(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		srv := NewServer("fuzz", "1")
		output := srv.HandleRaw(input)
		if output != nil && !json.Valid(output) {
			t.Fatalf("invalid JSON response: %s", output)
		}
	})
}
