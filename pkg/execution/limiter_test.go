package execution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestConcurrencyQueueAndCancellation(t *testing.T) {
	l, err := NewLimiter(1, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 2), make(chan struct{})
	h := l.Middleware(func(ctx context.Context, _ string, _ json.RawMessage) (*mcp.ToolResult, error) {
		started <- struct{}{}
		select {
		case <-release:
			return &mcp.ToolResult{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	first := make(chan error, 1)
	go func() { _, err := h(context.Background(), "test", nil); first <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() { _, err := h(ctx, "test", nil); second <- err }()
	deadline := time.Now().Add(time.Second)
	for len(l.admitted) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("second call did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	r, err := h(context.Background(), "test", nil)
	if err != nil || !r.IsError || !strings.Contains(r.Content[0].Text, "queue full") {
		t.Fatalf("queue not bounded: %+v %v", r, err)
	}
	select {
	case <-started:
		t.Fatal("queued call executed concurrently")
	default:
	}
	cancel()
	if err := <-second; err == nil {
		t.Fatal("cancelled queued call accepted")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if len(l.active) != 0 || len(l.admitted) != 0 {
		t.Fatal("execution slots leaked")
	}
}

func TestDeadlineAppliesToTool(t *testing.T) {
	l, _ := NewLimiter(1, 0, 20*time.Millisecond)
	h := l.Middleware(func(ctx context.Context, _ string, _ json.RawMessage) (*mcp.ToolResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if _, err := h(context.Background(), "test", nil); err == nil {
		t.Fatal("tool deadline not enforced")
	}
}

type policyTool struct{}

func (policyTool) Name() string                 { return "dangerous" }
func (policyTool) Description() string          { return "test" }
func (policyTool) InputSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (policyTool) Execute(context.Context, json.RawMessage) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{}, nil
}

func TestApprovalCannotComeFromArguments(t *testing.T) {
	for _, approved := range [][]string{nil, {"dangerous"}} {
		srv := mcp.NewServer("test", "1")
		srv.RegisterTool(policyTool{})
		srv.Use(Approval(approved))
		r, err := srv.ExecuteTool(context.Background(), "dangerous", json.RawMessage(`{"approved":true}`))
		if err != nil {
			t.Fatal(err)
		}
		if r.IsError != (len(approved) == 0) {
			t.Fatalf("approval policy: %+v", r)
		}
	}
}
