package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/tools/system/health"
	targettools "github.com/yasindce1998/redhands/tools/targetdb"
)

func TestCLICommandsAgainstActualSSEServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := mcp.NewServer("test", "1")
	db := targetdb.NewStore("", false)
	srv.RegisterTool(targettools.NewAddHostTool(db))
	srv.RegisterTool(targettools.NewListHostsTool(db))
	srv.RegisterTool(targettools.NewQueryFindingsTool(db))
	srv.RegisterTool(health.NewHealthCheck(nil))
	ac := auth.Config{Mode: "apikey", APIKey: "test-secret"}
	srv.SetRequestCheck(func(ctx context.Context) error { return auth.CheckContext(ac, ctx) })
	server := httptest.NewServer(srv.SSEHandler(ctx, mcp.HTTPOptions{AuthCheck: auth.HTTPAuthCheck(ac)}))
	defer server.Close()
	env := func(key string) string {
		switch key {
		case "REDHANDS_URL":
			return server.URL
		case "REDHANDS_API_KEY":
			return ac.APIKey
		case "REDHANDS_CLIENT_TIMEOUT":
			return "3s"
		}
		return ""
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"tools"}, "targetdb_add_host"},
		{[]string{"targets", "add", "192.0.2.1", "test-host"}, "added/updated"},
		{[]string{"targets"}, "test-host"},
		{[]string{"findings"}, "No findings"},
		{[]string{"status"}, "Health Check"},
	} {
		var out bytes.Buffer
		if err := run(ctx, tc.args, &out, env); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v output: %s", tc.args, out.String())
		}
	}
	var out bytes.Buffer
	if err := run(ctx, []string{"call", "targetdb_add_host", `{}`}, &out, env); err == nil {
		t.Fatal("tool error did not fail CLI")
	}
	if err := run(ctx, []string{"tools"}, &out, func(key string) string {
		if key == "REDHANDS_URL" {
			return server.URL
		}
		return ""
	}); err == nil {
		t.Fatal("missing API key accepted")
	}
}

func TestCLIRejectsBadInputBeforeConnecting(t *testing.T) {
	for _, args := range [][]string{{"call"}, {"call", "tool", `null`}, {"call", "tool", `[]`}, {"call", "tool", `invalid`}, {"targets", "remove"}, {"unknown"}} {
		if err := run(context.Background(), args, &bytes.Buffer{}, func(string) string { return "" }); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
