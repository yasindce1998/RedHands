package opsec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func successHandler(_ context.Context, _ string, _ json.RawMessage) (*mcp.ToolResult, error) {
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: "ok"}},
	}, nil
}

func TestMiddleware_LoudBypass(t *testing.T) {
	tr := NewTracker("")
	mw := NewMiddleware("loud", tr)

	handler := mw.Wrap(successHandler)
	result, err := handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.IsError {
		t.Error("loud profile should not block")
	}
	if tr.Count() != 0 {
		t.Error("loud profile should bypass IOC tracking via handler shortcut")
	}
}

func TestMiddleware_NormalTracksIOC(t *testing.T) {
	tr := NewTracker("")
	mw := NewMiddleware("normal", tr)
	mw.profile = &Profile{
		Name:         "test_nodelay",
		MinDelay:     0,
		MaxDelay:     0,
		MaxPerMinute: 100,
		MaxPerTarget: 100,
		JitterPct:    0,
	}

	handler := mw.Wrap(successHandler)
	result, err := handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result.IsError {
		t.Error("should succeed")
	}
	if tr.Count() != 1 {
		t.Errorf("IOC count = %d, want 1", tr.Count())
	}
}

func TestMiddleware_RateLimitTotal(t *testing.T) {
	tr := NewTracker("")
	mw := NewMiddleware("stealth", tr)
	mw.profile = &Profile{
		Name:         "test_strict",
		MinDelay:     0,
		MaxDelay:     0,
		MaxPerMinute: 2,
		MaxPerTarget: 10,
		JitterPct:    0,
	}

	handler := mw.Wrap(successHandler)

	for i := 0; i < 2; i++ {
		result, _ := handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
		if result.IsError {
			t.Fatalf("call %d should succeed", i+1)
		}
	}

	result, _ := handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.2"}`))
	if !result.IsError {
		t.Error("3rd call should be rate-limited (total: 2/min)")
	}
}

func TestMiddleware_RateLimitPerTarget(t *testing.T) {
	tr := NewTracker("")
	mw := NewMiddleware("stealth", tr)
	mw.profile = &Profile{
		Name:         "test_pertarget",
		MinDelay:     0,
		MaxDelay:     0,
		MaxPerMinute: 100,
		MaxPerTarget: 1,
		JitterPct:    0,
	}

	handler := mw.Wrap(successHandler)

	result, _ := handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
	if result.IsError {
		t.Fatal("first call should succeed")
	}

	result, _ = handler(context.Background(), "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
	if !result.IsError {
		t.Error("2nd call to same target should be rate-limited (1/target)")
	}
}

func TestMiddleware_CancelledContext(t *testing.T) {
	tr := NewTracker("")
	mw := NewMiddleware("normal", tr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handler := mw.Wrap(successHandler)
	result, err := handler(ctx, "nmap", json.RawMessage(`{"target":"10.0.0.1"}`))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result.IsError {
		t.Error("cancelled context should produce error result")
	}
}

func TestExtractTarget(t *testing.T) {
	tests := []struct {
		params string
		want   string
	}{
		{`{"target":"10.0.0.1"}`, "10.0.0.1"},
		{`{"host":"web.local"}`, "web.local"},
		{`{"ip":"192.168.1.1"}`, "192.168.1.1"},
		{`{"target":"a","host":"b"}`, "a"},
		{`{"other":"x"}`, ""},
		{`{}`, ""},
	}
	for _, tc := range tests {
		got := extractTarget(json.RawMessage(tc.params))
		if got != tc.want {
			t.Errorf("extractTarget(%s) = %q, want %q", tc.params, got, tc.want)
		}
	}
}

func TestMiddleware_SetProfile(t *testing.T) {
	mw := NewMiddleware("normal", NewTracker(""))
	if mw.CurrentProfile().Name != "normal" {
		t.Errorf("initial profile = %q", mw.CurrentProfile().Name)
	}
	mw.SetProfile("stealth")
	if mw.CurrentProfile().Name != "stealth" {
		t.Errorf("after SetProfile = %q", mw.CurrentProfile().Name)
	}
}
