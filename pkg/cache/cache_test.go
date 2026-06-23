package cache

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestCacheHitAndMiss(t *testing.T) {
	c := New(10, 5*time.Minute)

	result := &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: "cached"}},
	}

	key := MakeKey("test_tool", json.RawMessage(`{"target":"1.2.3.4"}`))
	c.Set(key, result)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Content[0].Text != "cached" {
		t.Errorf("unexpected cached result: %v", got)
	}

	_, ok = c.Get("nonexistent")
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestCacheExpiry(t *testing.T) {
	c := New(10, 50*time.Millisecond)

	result := &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: "cached"}},
	}

	key := MakeKey("test_tool", json.RawMessage(`{}`))
	c.Set(key, result)

	time.Sleep(60 * time.Millisecond)

	_, ok := c.Get(key)
	if ok {
		t.Fatal("expected cache miss after expiry")
	}
}

func TestCacheEviction(t *testing.T) {
	c := New(2, 5*time.Minute)

	r1 := &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "first"}}}
	r2 := &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "second"}}}
	r3 := &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "third"}}}

	c.Set("k1", r1)
	time.Sleep(time.Millisecond)
	c.Set("k2", r2)
	time.Sleep(time.Millisecond)
	c.Set("k3", r3)

	if _, ok := c.Get("k1"); ok {
		t.Error("expected k1 to be evicted")
	}
	if _, ok := c.Get("k3"); !ok {
		t.Error("expected k3 to be present")
	}
}
