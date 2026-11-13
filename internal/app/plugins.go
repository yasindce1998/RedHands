package app

import (
	"log"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/plugin"
)

func SetupPlugins(srv *mcp.Server, cfg *config.Config, execr executor.Executor) func() {
	managed := make(map[string]bool)
	reload := func(path string) error {
		next := make(map[string]bool)
		for _, tool := range plugin.LoadPlugins(cfg.PluginsDir, execr) {
			if _, exists := srv.GetTool(tool.Name()); exists && !managed[tool.Name()] {
				log.Printf("plugin %q conflicts with a built-in tool; skipped", tool.Name())
				continue
			}
			if err := srv.RegisterTool(tool); err != nil {
				log.Printf("plugin %q rejected: %v", tool.Name(), err)
				continue
			}
			next[tool.Name()] = true
		}
		for name := range managed {
			if !next[name] {
				srv.UnregisterTool(name)
			}
		}
		managed = next
		return nil
	}
	_ = reload("")

	if cfg.PluginsDir == "" {
		return func() {}
	}

	watcher := plugin.NewWatcher(cfg.PluginsDir, cfg.PluginPollInterval, reload)
	watcher.Start()
	return watcher.Stop
}
