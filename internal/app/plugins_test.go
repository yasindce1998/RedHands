package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/tools/intelligence"
)

func TestPluginReloadPreservesBuiltinsAndRemovesDeletedTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	write := func(name string) {
		t.Helper()
		data, _ := json.Marshal(map[string]any{"name": name, "binary": "echo", "input_schema": map[string]string{"type": "object"}})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	srv := mcp.NewServer("test", "1")
	builtin := intelligence.NewMitreLookupTool()
	srv.RegisterTool(builtin)
	write("mitre_lookup")
	cfg := config.Load()
	cfg.PluginsDir, cfg.PluginPollInterval = dir, 5*time.Millisecond
	stop := SetupPlugins(srv, &cfg, executor.NewMock())
	defer stop()
	if tool, _ := srv.GetTool("mitre_lookup"); tool != builtin {
		t.Fatal("plugin replaced built-in")
	}
	write("custom_one")
	waitFor := func(check func() bool) {
		t.Helper()
		deadline := time.After(3 * time.Second)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for !check() {
			select {
			case <-deadline:
				t.Fatal("plugin reload timed out")
			case <-ticker.C:
			}
		}
	}
	waitFor(func() bool { _, ok := srv.GetTool("custom_one"); return ok })
	write("custom_two")
	waitFor(func() bool {
		_, old := srv.GetTool("custom_one")
		_, next := srv.GetTool("custom_two")
		return !old && next
	})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(func() bool { _, ok := srv.GetTool("custom_two"); return !ok })
	if tool, _ := srv.GetTool("mitre_lookup"); tool != builtin {
		t.Fatal("builtin removed during reload")
	}
}
