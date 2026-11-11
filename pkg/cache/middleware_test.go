package cache

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestOnlyPureToolsAreCachedPerIdentity(t *testing.T) {
	count := 0
	h := MiddlewareWithPolicy(New(10, time.Minute), func(ctx context.Context, name string) (string, bool) {
		identity, _ := ctx.Value(auth.ContextKeyIdentity).(string)
		return identity, name == "mitre_lookup"
	})(func(context.Context, string, json.RawMessage) (*mcp.ToolResult, error) {
		count++
		return &mcp.ToolResult{Content: []mcp.ContentBlock{{Type: "text", Text: "ok"}}}, nil
	})
	ctx := auth.InjectAuthContext(context.Background(), "a")
	for range 2 {
		_, _ = h(ctx, "mitre_lookup", json.RawMessage(`{}`))
	}
	if count != 1 {
		t.Fatal("pure function not cached")
	}
	_, _ = h(auth.InjectAuthContext(context.Background(), "b"), "mitre_lookup", json.RawMessage(`{}`))
	if count != 2 {
		t.Fatal("cache shared between identities")
	}
	for _, name := range []string{"targetdb_add_host", "targetdb_list_hosts", "engagement_switch", "nmap_port_scan", "credstore_search"} {
		before := count
		for range 2 {
			_, _ = h(ctx, name, json.RawMessage(`{}`))
		}
		if count != before+2 {
			t.Errorf("unsafe caching for %s", name)
		}
	}
}

func TestDisabledCache(t *testing.T) {
	c := New(0, time.Minute)
	c.Set("key", &mcp.ToolResult{})
	if _, ok := c.Get("key"); ok {
		t.Fatal("disabled cache stored result")
	}
}
