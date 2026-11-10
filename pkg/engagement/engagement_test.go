package engagement

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

func TestMatchScope(t *testing.T) {
	for _, tc := range []struct {
		target, scope string
		want          bool
	}{
		{"192.0.2.8", "192.0.2.0/24", true},
		{"192.0.2.128/25", "192.0.2.0/24", true},
		{"192.0.2.0/23", "192.0.2.0/24", false},
		{"198.51.100.8", "192.0.2.0/24", false},
		{"https://WEB.example.com:443/login", "*.example.com", true},
		{"example.com.evil.test", "*.example.com", false},
		{"[2001:db8::1]:443", "2001:db8::/32", true},
		{"https://192.0.2.8/path", "192.0.2.0/24", true},
	} {
		if got := matchScope(tc.target, tc.scope); got != tc.want {
			t.Errorf("matchScope(%q, %q)=%v, want %v", tc.target, tc.scope, got, tc.want)
		}
	}
}

func TestScopeChecksAllTargetsAndURLs(t *testing.T) {
	mgr := NewManager(t.TempDir())
	if _, err := mgr.Create("test", "client", []string{"192.0.2.0/24", "*.example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, params string
		allowed      bool
	}{
		{"masscan_scan", `{"targets":"192.0.2.1,198.51.100.1"}`, false},
		{"httpx_probe", `{"targets":["https://web.example.com", "https://evil.test"]}`, false},
		{"katana_crawl", `{"url":"https://web.example.com:443/path"}`, true},
		{"nmap_port_scan", `{"target":"192.0.2.8"}`, true},
		{"nmap_port_scan", `{"target":"198.51.100.8"}`, false},
		{"barzakh_scan", `{"target":"firmware.bin"}`, true},
		{"coercion_check", `{"target":"192.0.2.8", "domain":"CREDENTIAL-REALM"}`, true},
	} {
		called := false
		h := mgr.ScopeMiddleware(func(context.Context, string, json.RawMessage) (*mcp.ToolResult, error) {
			called = true
			return &mcp.ToolResult{}, nil
		})
		_, err := h(context.Background(), tc.name, json.RawMessage(tc.params))
		if err != nil {
			t.Fatal(err)
		}
		if called != tc.allowed {
			t.Errorf("%s %s: called=%v", tc.name, tc.params, called)
		}
	}
}
